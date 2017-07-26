/*
 * *** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is part of dcm4che, an implementation of DICOM(TM) in
 * Java(TM), hosted at https://github.com/dcm4che.
 *
 * The Initial Developer of the Original Code is
 * J4Care.
 * Portions created by the Initial Developer are Copyright (C) 2017
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * See @authors listed below
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * *** END LICENSE BLOCK *****
 */

package org.dcm4chee.arc.audit;

import org.dcm4che3.audit.*;
import org.dcm4che3.conf.api.ConfigurationException;
import org.dcm4che3.conf.api.IApplicationEntityCache;
import org.dcm4che3.data.*;
import org.dcm4che3.hl7.HL7Segment;
import org.dcm4che3.io.DicomOutputStream;
import org.dcm4che3.net.*;
import org.dcm4che3.net.audit.AuditLogger;
import org.dcm4che3.net.audit.AuditLoggerDeviceExtension;
import org.dcm4che3.util.StringUtils;
import org.dcm4chee.arc.ConnectionEvent;
import org.dcm4chee.arc.conf.ArchiveDeviceExtension;
import org.dcm4chee.arc.conf.RejectionNote;
import org.dcm4chee.arc.conf.ShowPatientInfo;
import org.dcm4chee.arc.delete.StudyDeleteContext;
import org.dcm4chee.arc.entity.Patient;
import org.dcm4chee.arc.entity.RejectionState;
import org.dcm4chee.arc.event.InstancesRetrieved;
import org.dcm4chee.arc.event.RejectionNoteSent;
import org.dcm4chee.arc.exporter.ExportContext;
import org.dcm4chee.arc.patient.PatientMgtContext;
import org.dcm4chee.arc.procedure.ProcedureContext;
import org.dcm4chee.arc.query.QueryContext;
import org.dcm4chee.arc.retrieve.InstanceLocations;
import org.dcm4chee.arc.retrieve.RetrieveContext;
import org.dcm4chee.arc.stgcmt.StgCmtEventInfo;
import org.dcm4chee.arc.store.StoreContext;
import org.dcm4chee.arc.store.StoreSession;
import org.dcm4chee.arc.study.StudyMgtContext;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;

/**
 * @author Vrinda Nayak <vrinda.nayak@j4care.com>
 * @author Gunter Zeilinger <gunterze@gmail.com>
 * @since Feb 2016
 */
@ApplicationScoped
public class AuditService {
    private final Logger LOG = LoggerFactory.getLogger(AuditService.class);
        private final String keycloakClassName = "org.keycloak.KeycloakSecurityContext";

    @Inject
    private Device device;

    @Inject
    private IApplicationEntityCache aeCache;

    @Inject
    private AuditEmitter auditEmitter;

    void spoolApplicationActivity(AuditServiceUtils.EventType eventType, HttpServletRequest req) {
        if (eventType == null)
            return;
        LinkedHashSet<Object> objs = new LinkedHashSet<>();
        objs.add(new AuditInfo(new BuildAuditInfo.Builder().calledAET(getAET(device)).build()));
        if (req != null) {
            String callingUser = getPreferredUsername(req);
            objs.add(new AuditInfo(
                    new BuildAuditInfo.Builder().callingAET(callingUser).callingHost(req.getRemoteAddr()).build()));
        }
        writeSpoolFile(eventType, objs);
    }

    void spoolInstancesDeleted(StoreContext ctx) {
        if (isExternalRejectionSameSourceDest(ctx))
            return;

        LinkedHashSet<Object> objs = new LinkedHashSet<>();
        objs.add(new AuditInfo(getAIStoreCtx(ctx)));
        addSOPRefs(ctx, objs);
        AuditServiceUtils.EventType eventType = ctx.getStoredInstance().getSeries().getStudy().getRejectionState()== RejectionState.COMPLETE
            ? AuditServiceUtils.EventType.RJ_COMPLET : AuditServiceUtils.EventType.RJ_PARTIAL;
        writeSpoolFile(eventType, objs);
    }

    private void addSOPRefs(StoreContext ctx, LinkedHashSet<Object> objs) {
        for (Attributes studyRef : ctx.getAttributes().getSequence(Tag.CurrentRequestedProcedureEvidenceSequence))
            for (Attributes seriesRef : studyRef.getSequence(Tag.ReferencedSeriesSequence))
                for (Attributes sopRef : seriesRef.getSequence(Tag.ReferencedSOPSequence))
                    objs.add(sopInfoForAudit(sopRef));
    }

    private boolean isExternalRejectionSameSourceDest(StoreContext ctx) {
        StoreSession ss = ctx.getStoreSession();
        return ctx.getRejectionNote() != null && ss.getHttpRequest() == null && ss.getCallingAET().equals(ss.getCalledAET());
    }

    void spoolStudyDeleted(StudyDeleteContext ctx) {
        LinkedHashSet<Object> objs = new LinkedHashSet<>();
        HttpServletRequest request = ctx.getHttpRequest();
        BuildAuditInfo i = request != null ? buildPermDeletionAuditInfoForWeb(request, ctx)
                : buildPermDeletionAuditInfoForScheduler(ctx);
        AuditServiceUtils.EventType eventType = request != null ? AuditServiceUtils.EventType.PRMDLT_WEB : AuditServiceUtils.EventType.PRMDLT_SCH;
        objs.add(new AuditInfo(i));
        for (org.dcm4chee.arc.entity.Instance instance : ctx.getInstances())
            objs.add(sopInfoForAudit(instance.getAttributes()));
        writeSpoolFile(eventType, objs);
    }

    void spoolExternalRejection(RejectionNoteSent rejectionNoteSent) throws ConfigurationException {
        LinkedHashSet<Object> deleteObjs = new LinkedHashSet<>();
        Attributes attrs = rejectionNoteSent.getRejectionNote();
        Attributes codeItem = attrs.getSequence(Tag.ConceptNameCodeSequence).get(0);
        Code code = new Code(codeItem.getString(Tag.CodeValue), codeItem.getString(Tag.CodingSchemeDesignator), null, "?");
        RejectionNote rjNote = device.getDeviceExtension(ArchiveDeviceExtension.class).getRejectionNote(code);
        HttpServletRequest req = rejectionNoteSent.getRequest();
        String callingAET = req != null
                ? getPreferredUsername(req)
                : rejectionNoteSent.getLocalAET();
        String calledAET = req != null
                ? req.getRequestURI() : rejectionNoteSent.getRemoteAET();
        String callingHost = req != null
                ? req.getRemoteHost() : toHost(rejectionNoteSent.getLocalAET());
        deleteObjs.add(new AuditInfo(new BuildAuditInfo.Builder()
                .callingAET(callingAET)
                .callingHost(callingHost)
                .calledAET(calledAET)
                .calledHost(toHost(rejectionNoteSent.getRemoteAET()))
                .outcome(String.valueOf(rjNote.getRejectionNoteType()))
                .patientIDAndName(toPIDAndName(attrs))
                .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(attrs))
                .build()));
        HashMap<String, HashSet<String>> sopClassMap = new HashMap<>();
        for (Attributes studyRef : attrs.getSequence(Tag.CurrentRequestedProcedureEvidenceSequence))
            for (Attributes refSer : studyRef.getSequence(Tag.ReferencedSeriesSequence))
                for (Attributes refSop : refSer.getSequence(Tag.ReferencedSOPSequence))
                    buildSOPClassMap(sopClassMap, refSop.getString(Tag.ReferencedSOPClassUID),
                            refSop.getString(Tag.ReferencedSOPInstanceUID));
        for (Map.Entry<String, HashSet<String>> entry : sopClassMap.entrySet()) {
            deleteObjs.add(new AuditInfo(new BuildAuditInfo.Builder().sopCUID(entry.getKey())
                    .sopIUID(String.valueOf(entry.getValue().size())).build()));
        }
        AuditServiceUtils.EventType clientET = rejectionNoteSent.isStudyDeleted()
                ? AuditServiceUtils.EventType.PRMDLT_WEB
                : AuditServiceUtils.EventType.RJ_PARTIAL;
        writeSpoolFile(clientET, deleteObjs);
        if (rejectionNoteSent.getLocalAET().equals(rejectionNoteSent.getRemoteAET())) {
            AuditServiceUtils.EventType serverET = rejectionNoteSent.isStudyDeleted()
                    ? AuditServiceUtils.EventType.RJ_COMPLET
                    : AuditServiceUtils.EventType.RJ_PARTIAL;
            writeSpoolFile(serverET, deleteObjs);
        }
    }
    private String toHost(String aet) throws ConfigurationException {
        ApplicationEntity ae = aeCache.findApplicationEntity(aet);
        StringBuilder b = new StringBuilder();
        if (ae != null) {
            List<Connection> conns = ae.getConnections();
            b.append(conns.get(0).getHostname());
            for (int i = 1; i < conns.size(); i++)
                b.append(';').append(conns.get(i).getHostname());
        }
        return b.toString();
    }


    private BuildAuditInfo buildPermDeletionAuditInfoForWeb(HttpServletRequest req, StudyDeleteContext ctx) {
        String callingAET = getPreferredUsername(req);
        return new BuildAuditInfo.Builder().callingAET(callingAET).callingHost(req.getRemoteHost()).calledAET(req.getRequestURI())
                .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(ctx.getStudy().getAttributes()))
                .patientIDAndName(toPIDAndName(ctx.getPatient().getAttributes()))
                .outcome(getOD(ctx.getException()))
                .build();
    }

    private BuildAuditInfo buildPermDeletionAuditInfoForScheduler(StudyDeleteContext ctx) {
        return new BuildAuditInfo.Builder()
                .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(ctx.getStudy().getAttributes()))
                .patientIDAndName(toPIDAndName(ctx.getPatient().getAttributes()))
                .outcome(getOD(ctx.getException()))
                .build();
    }



    void spoolInstancesRetrieved(InstancesRetrieved instancesRetrieved) {
        Attributes keys = instancesRetrieved.getKeys();
        LinkedHashSet<Object> obj = new LinkedHashSet<>();
        BuildAuditInfo i = new BuildAuditInfo.Builder()
                .callingAET(getPreferredUsername(instancesRetrieved.getRequest()))
                .callingHost(instancesRetrieved.getRequest().getRemoteAddr())
                .calledHost(instancesRetrieved.getRemoteAET())
                .calledAET(instancesRetrieved.getRequest().getRequestURI())
                .moveAET(instancesRetrieved.getLocalAET())
                .destAET(instancesRetrieved.getDestinationAET())
                .failedIUIDShow(instancesRetrieved.failed() > 0)
                .warning(String.valueOf(instancesRetrieved.warning()))
                .studyUID(keys.getString(Tag.StudyInstanceUID))
                .build();
        obj.add(new AuditInfo(i));
        writeSpoolFile(AuditServiceUtils.EventType.INST_RETRV, obj);
    }

    void spoolConnectionRejected(ConnectionEvent event) {
        LinkedHashSet<Object> obj = new LinkedHashSet<>();
        BuildAuditInfo i = new BuildAuditInfo.Builder().callingHost(event.getSocket().getRemoteSocketAddress().toString())
                .calledHost(event.getConnection().getHostname()).outcome(event.getException().getMessage()).build();
        obj.add(new AuditInfo(i));
        writeSpoolFile(AuditServiceUtils.EventType.CONN__RJCT, obj);
    }

    void spoolQuery(QueryContext ctx) {
        ArchiveDeviceExtension arcDev = device.getDeviceExtension(ArchiveDeviceExtension.class);
        boolean auditAggregate = arcDev.isAuditAggregate();
        AuditLoggerDeviceExtension ext = device.getDeviceExtension(AuditLoggerDeviceExtension.class);
        AuditServiceUtils.EventType eventType = AuditServiceUtils.EventType.forQuery(ctx);
        AuditInfo auditInfo = ctx.getHttpRequest() != null ? createAuditInfoForQIDO(ctx) : createAuditInfoForFIND(ctx);
        for (AuditLogger auditLogger : ext.getAuditLoggers()) {
            if (auditLogger.isInstalled()) {
                Path directory = Paths.get(StringUtils.replaceSystemProperties(arcDev.getAuditSpoolDirectory()),
                                auditLogger.getCommonName().replaceAll(" ", "_"));
                try {
                    Files.createDirectories(directory);
                    Path file = Files.createTempFile(directory, String.valueOf(eventType), null);
                    try (BufferedOutputStream out = new BufferedOutputStream(
                            Files.newOutputStream(file, StandardOpenOption.APPEND))) {
                        new DataOutputStream(out).writeUTF(auditInfo.toString());
                        if (ctx.getAssociation() != null) {
                            try (DicomOutputStream dos = new DicomOutputStream(out, UID.ImplicitVRLittleEndian)) {
                                dos.writeDataset(null, ctx.getQueryKeys());
                            } catch (Exception e) {
                                LOG.warn("Failed to create DicomOutputStream : ", e);
                            }
                        }
                    }
                    if (!auditAggregate)
                        auditAndProcessFile(auditLogger, file);
                } catch (Exception e) {
                    LOG.warn("Failed to write to Audit Spool File - {}", auditLogger.getCommonName(), e);
                }
            }
        }
    }

    void auditAndProcessFile(AuditLogger auditLogger, Path file) {
        try {
            auditEmitter.aggregateAuditMessage(auditLogger, file);
            Files.delete(file);
        } catch (Exception e) {
            LOG.warn("Failed to process Audit Spool File - {}", auditLogger.getCommonName(), file, e);
            try {
                Files.move(file, file.resolveSibling(file.getFileName().toString() + ".failed"));
            } catch (IOException e1) {
                LOG.warn("Failed to mark Audit Spool File - {} as failed", auditLogger.getCommonName(), file, e);
            }
        }
    }

    private AuditInfo createAuditInfoForFIND(QueryContext ctx) {
        return new AuditInfo(
                new BuildAuditInfo.Builder()
                        .callingHost(ctx.getRemoteHostName())
                        .callingAET(ctx.getCallingAET())
                        .calledAET(ctx.getCalledAET())
                        .queryPOID(ctx.getSOPClassUID())
                        .build());
    }

    private AuditInfo createAuditInfoForQIDO(QueryContext ctx) {
        HttpServletRequest httpRequest = ctx.getHttpRequest();
        return new AuditInfo(
                new BuildAuditInfo.Builder()
                        .callingHost(ctx.getRemoteHostName())
                        .callingAET(getPreferredUsername(httpRequest))
                        .calledAET(httpRequest.getRequestURI())
                        .queryPOID(ctx.getSearchMethod())
                        .queryString(httpRequest.getRequestURI() + httpRequest.getQueryString())
                        .build());
    }

    void spoolInstanceStored(StoreContext ctx) {
        AuditServiceUtils.EventType eventType = AuditServiceUtils.EventType.forInstanceStored(ctx);
        if (isDuplicateReceivedInstance(eventType))
            return;
        String callingAET = ctx.getStoreSession().getHttpRequest() != null
                ? ctx.getStoreSession().getHttpRequest().getRemoteAddr() : ctx.getStoreSession().getCallingAET().replace('|', '-');
        String fileName = getFileName(eventType, callingAET, ctx.getStoreSession().getCalledAET(), ctx.getStudyInstanceUID());
        BuildAuditInfo i = getAIStoreCtx(ctx);
        BuildAuditInfo iI = new BuildAuditInfo.Builder().sopCUID(ctx.getSopClassUID()).sopIUID(ctx.getSopInstanceUID())
                .mppsUID(StringUtils.maskNull(ctx.getMppsInstanceUID(), " ")).build();
        writeSpoolFileStoreOrWadoRetrieve(fileName, new AuditInfo(i), new AuditInfo(iI));
    }

    private boolean isDuplicateReceivedInstance(AuditServiceUtils.EventType eventType) {
        return eventType == null;
    }

    void spoolInstanceRetrieved(RetrieveContext ctx) {
        HttpServletRequest req = ctx.getHttpRequest();
        Collection<InstanceLocations> il = ctx.getMatches();
        Attributes attrs = new Attributes();
        for (InstanceLocations i : il)
            attrs = i.getAttributes();
        String fileName = getFileName(AuditServiceUtils.EventType.WADO___URI, req.getRemoteAddr(),
                ctx.getLocalAETitle(), ctx.getStudyInstanceUIDs()[0]);
        String callingAET = getPreferredUsername(req);
        AuditInfo i = new AuditInfo(new BuildAuditInfo.Builder().callingHost(req.getRemoteAddr()).callingAET(callingAET)
                .calledAET(req.getRequestURI())
                .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(attrs))
                .patientIDAndName(toPIDAndName(attrs))
                .outcome(null != ctx.getException() ? ctx.getException().getMessage() : null).build());
        writeSpoolFileStoreOrWadoRetrieve(fileName, i, sopInfoForAudit(attrs));
    }

    void buildSOPClassMap(HashMap<String, HashSet<String>> sopClassMap, String cuid, String iuid) {
        HashSet<String> iuids = sopClassMap.get(cuid);
        if (iuids == null) {
            iuids = new HashSet<>();
            sopClassMap.put(cuid, iuids);
        }
        iuids.add(iuid);
    }

    void spoolPartialRetrieve(RetrieveContext ctx, HashSet<AuditServiceUtils.EventType> et) {
        List<String> failedList = Arrays.asList(ctx.failedSOPInstanceUIDs());
        Collection<InstanceLocations> instanceLocations = ctx.getMatches();
        HashSet<InstanceLocations> failed = new HashSet<>();
        HashSet<InstanceLocations> success = new HashSet<>();
        success.addAll(instanceLocations);
        for (InstanceLocations il : instanceLocations) {
            if (failedList.contains(il.getSopInstanceUID())) {
                failed.add(il);
                success.remove(il);
            }
        }
        String etFile;
        for (AuditServiceUtils.EventType eventType : et) {
            if (eventType.eventClass == AuditServiceUtils.EventClass.RETRIEVE_ERR)
                spoolRetrieve(eventType, ctx, failed);
            else
                spoolRetrieve(eventType, ctx, success);
        }
    }

    void spoolRetrieve(AuditServiceUtils.EventType eventType, RetrieveContext ctx, Collection<InstanceLocations> il) {
        LinkedHashSet<Object> obj = new LinkedHashSet<>();
        HttpServletRequest req = ctx.getHttpRequest();
        String destAET = req != null ? getPreferredUsername(req) : ctx.getDestinationAETitle();

        String outcome = (eventType.eventClass == AuditServiceUtils.EventClass.BEGIN_TRF && ctx.getException() != null)
                || eventType.eventClass == AuditServiceUtils.EventClass.RETRIEVE_ERR
                ? getFailOutcomeDesc(ctx) : null;

        String warning = eventType.eventClass == AuditServiceUtils.EventClass.RETRIEVE && ctx.warning() != 0
                ? ctx.warning() == ctx.getMatches().size()
                    ? "Warnings on retrieve of all instances"
                    : "Warnings on retrieve of " + ctx.warning() + " instances"
                : null;

        boolean failedIUIDShow = eventType.eventClass == AuditServiceUtils.EventClass.RETRIEVE_ERR && ctx.failedSOPInstanceUIDs().length > 0;
        BuildAuditInfo i = new BuildAuditInfo.Builder().calledAET(req != null ? req.getRequestURI() : ctx.getLocalAETitle())
                .destAET(destAET).destNapID(null != req ? req.getRemoteAddr() : ctx.getDestinationHostName()).warning(warning)
                .callingHost(ctx.getRequestorHostName()).moveAET(ctx.getMoveOriginatorAETitle()).outcome(outcome).failedIUIDShow(failedIUIDShow).build();
        obj.add(new AuditInfo(i));
        addInstanceInfoForRetrieve(obj, il);
        addInstanceInfoForRetrieve(obj, ctx.getCStoreForwards());
        writeSpoolFile(eventType, obj);
    }

    private void addInstanceInfoForRetrieve(LinkedHashSet<Object> obj, Collection<InstanceLocations> instanceLocations) {
        for (InstanceLocations instanceLocation : instanceLocations) {
            Attributes attrs = instanceLocation.getAttributes();
            BuildAuditInfo iI = new BuildAuditInfo.Builder()
                    .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(attrs))
                    .sopCUID(sopCUID(attrs)).sopIUID(attrs.getString(Tag.SOPInstanceUID))
                    .patientIDAndName(toPIDAndName(attrs))
                    .build();
            obj.add(new AuditInfo(iI));
        }
    }

    void spoolPatientRecord(PatientMgtContext ctx) {
        HashSet<AuditServiceUtils.EventType> et = AuditServiceUtils.EventType.forHL7(ctx);
        for (AuditServiceUtils.EventType eventType : et) {
            LinkedHashSet<Object> obj = new LinkedHashSet<>();
            String source = null;
            String dest = null;
            String hl7MessageType = null;
            HL7Segment msh = ctx.getHL7MessageHeader();
            if (ctx.getHttpRequest() != null) {
                source = getPreferredUsername(ctx.getHttpRequest());
                dest = ctx.getCalledAET();
            }
            if (msh != null) {
                source = msh.getSendingApplicationWithFacility();
                dest = msh.getReceivingApplicationWithFacility();
                hl7MessageType = msh.getMessageType();
            }
            if (ctx.getAssociation() != null) {
                source = ctx.getAssociation().getCallingAET();
                dest = ctx.getAssociation().getCalledAET();
            }
            Attributes attrs = eventType == AuditServiceUtils.EventType.PAT_DELETE && ctx.getPreviousAttributes() != null
                                ? ctx.getPreviousAttributes()
                                : ctx.getAttributes();
            String callingHost = ctx.getHttpRequest() != null
                    ? ctx.getHttpRequest().getRemoteAddr()
                    : msh != null || ctx.getAssociation() != null
                    ? ctx.getRemoteHostName() : null;
            BuildAuditInfo i = new BuildAuditInfo.Builder().callingHost(callingHost)
                    .callingAET(source).calledAET(dest)
                    .patientIDAndName(toPIDAndName(attrs))
                    .outcome(getOD(ctx.getException())).hl7MessageType(hl7MessageType).build();
            obj.add(new AuditInfo(i));
            writeSpoolFile(eventType, obj);
        }
    }

    void spoolProcedureRecord(ProcedureContext ctx) {
        HashSet<AuditServiceUtils.EventType> et = AuditServiceUtils.EventType.forProcedure(ctx.getEventActionCode());
        for (AuditServiceUtils.EventType eventType : et) {
            LinkedHashSet<Object> obj = new LinkedHashSet<>();
            BuildAuditInfo i = ctx.getHttpRequest() != null
                    ? buildAuditInfoFORRestful(ctx)
                    : ctx.getAssociation() != null ? buildAuditInfoForAssociation(ctx) : buildAuditInfoFORHL7(ctx);
            obj.add(new AuditInfo(i));
            writeSpoolFile(eventType, obj);
        }
    }

    private BuildAuditInfo buildAuditInfoForAssociation(ProcedureContext ctx) {
        Association as = ctx.getAssociation();
        Attributes attr = ctx.getAttributes();
        Patient p = ctx.getPatient();
        BuildAuditInfo i = new BuildAuditInfo.Builder().callingHost(ctx.getRemoteHostName()).callingAET(as.getCallingAET())
                .calledAET(as.getCalledAET())
                .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(attr))
                .patientIDAndName(toPIDAndName(p.getAttributes()))
                .outcome(getOD(ctx.getException())).build();
        return i;
    }

    private BuildAuditInfo buildAuditInfoFORRestful(ProcedureContext ctx) {
        Attributes attr = ctx.getAttributes();
        HttpServletRequest req  = ctx.getHttpRequest();
        BuildAuditInfo i = new BuildAuditInfo.Builder().callingHost(ctx.getRemoteHostName())
                .callingAET(getPreferredUsername(req))
                .calledAET(ctx.getCalledAET())
                .patientIDAndName(toPIDAndName(attr))
                .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(attr))
                .outcome(getOD(ctx.getException())).build();
        return i;
    }

    private BuildAuditInfo buildAuditInfoFORHL7(ProcedureContext ctx) {
        Attributes attr = ctx.getAttributes();
        BuildAuditInfo i = new BuildAuditInfo.Builder().callingHost(ctx.getRemoteHostName())
                .callingAET(ctx.getHL7MessageHeader().getSendingApplicationWithFacility())
                .calledAET(ctx.getHL7MessageHeader().getReceivingApplicationWithFacility())
                .patientIDAndName(toPIDAndName(attr))
                .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(attr))
                .outcome(getOD(ctx.getException())).build();
        return i;
    }

    void spoolProcedureRecord(StudyMgtContext ctx) {
        HashSet<AuditServiceUtils.EventType> et = AuditServiceUtils.EventType.forProcedure(ctx.getEventActionCode());
        for (AuditServiceUtils.EventType eventType : et) {
            LinkedHashSet<Object> obj = new LinkedHashSet<>();
            String callingAET = getPreferredUsername(ctx.getHttpRequest());
            Attributes pAttr = ctx.getStudy() != null ? ctx.getStudy().getPatient().getAttributes() : null;
            BuildAuditInfo i = new BuildAuditInfo.Builder().callingHost(ctx.getHttpRequest().getRemoteHost()).callingAET(callingAET)
                    .calledAET(ctx.getApplicationEntity().getAETitle())
                    .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(ctx.getAttributes()))
                    .patientIDAndName(toPIDAndName(pAttr))
                    .outcome(getOD(ctx.getException())).build();
            obj.add(new AuditInfo(i));
            writeSpoolFile(eventType, obj);
        }
    }

    void spoolProvideAndRegister(ExportContext ctx) {
        LinkedHashSet<Object> obj = new LinkedHashSet<>();
        Attributes xdsiManifest = ctx.getXDSiManifest();
        if (xdsiManifest == null)
            return;
        URI dest = ctx.getExporter().getExporterDescriptor().getExportURI();
        String schemeSpecificPart = dest.getSchemeSpecificPart();
        String calledHost = schemeSpecificPart.substring(schemeSpecificPart.indexOf("://")+3, schemeSpecificPart.lastIndexOf(":"));
        BuildAuditInfo i = new BuildAuditInfo.Builder().callingAET(getAET(device)).calledAET(dest.toString())
                .calledHost(calledHost).outcome(null != ctx.getException() ? ctx.getException().getMessage() : null)
                .patientIDAndName(toPIDAndName(xdsiManifest))
                .submissionSetUID(ctx.getSubmissionSetUID()).build();
        obj.add(new AuditInfo(i));
        writeSpoolFile(AuditServiceUtils.EventType.PROV_REGIS, obj);
    }

    void spoolStgCmt(StgCmtEventInfo stgCmtEventInfo) {
        try {
            ArchiveDeviceExtension arcDev = device.getDeviceExtension(ArchiveDeviceExtension.class);
            String callingAET = stgCmtEventInfo.getRequest() != null
                                    ? getPreferredUsername(stgCmtEventInfo.getRequest())
                                    : stgCmtEventInfo.getRemoteAET();
            String calledAET = stgCmtEventInfo.getRequest() != null
                                ? stgCmtEventInfo.getRequest().getRequestURI()
                                : stgCmtEventInfo.getLocalAET();
            ApplicationEntity remoteAE = stgCmtEventInfo.getRemoteAET() != null
                    ? aeCache.findApplicationEntity(stgCmtEventInfo.getRemoteAET()) : null;
            String callingHost = remoteAE != null
                    ? remoteAE.getConnections().get(0).getHostname() : stgCmtEventInfo.getRequest().getRemoteHost();
            Attributes eventInfo = stgCmtEventInfo.getExtendedEventInfo();
            Sequence failed = eventInfo.getSequence(Tag.FailedSOPSequence);
            Sequence success = eventInfo.getSequence(Tag.ReferencedSOPSequence);
            String studyUID = eventInfo.getStrings(Tag.StudyInstanceUID) != null
                    ? buildStrings(eventInfo.getStrings(Tag.StudyInstanceUID)) : arcDev.auditUnknownStudyInstanceUID();
            if (failed != null && !failed.isEmpty()) {
                Set<String> failureReasons = new HashSet<>();
                Set<AuditInfo> aiSet = new HashSet<>();
                LinkedHashSet<Object> objs = new LinkedHashSet<>();
                for (Attributes item : failed) {
                    String outcome = item.getInt(Tag.FailureReason, 0) == Status.NoSuchObjectInstance
                            ? "NoSuchObjectInstance" : item.getInt(Tag.FailureReason, 0) == Status.ClassInstanceConflict
                            ? "ClassInstanceConflict" : "ProcessingFailure";
                    failureReasons.add(outcome);
                    aiSet.add(sopInfoForAudit(item));
                }
                BuildAuditInfo i = new BuildAuditInfo.Builder().callingAET(callingAET).callingHost(callingHost)
                        .calledAET(calledAET).studyUID(studyUID)
                        .patientIDAndName(toPIDAndName(eventInfo))
                        .outcome(buildStrings(failureReasons.toArray(new String[failureReasons.size()]))).build();
                objs.add(new AuditInfo(i));
                objs.addAll(aiSet);
                writeSpoolFile(AuditServiceUtils.EventType.STG_CMT__E, objs);
            }
            if (success != null && !success.isEmpty()) {
                LinkedHashSet<Object> objs = new LinkedHashSet<>();
                BuildAuditInfo i = new BuildAuditInfo.Builder().callingAET(callingAET)
                        .callingHost(callingHost).calledAET(calledAET)
                        .patientIDAndName(toPIDAndName(eventInfo))
                        .studyUID(studyUID).build();
                objs.add(new AuditInfo(i));
                for (Attributes item : success)
                    objs.add(sopInfoForAudit(item));
                writeSpoolFile(AuditServiceUtils.EventType.STG_CMT__P, objs);
            }
        } catch (ConfigurationException e) {
            LOG.error(e.getMessage(), stgCmtEventInfo.getRemoteAET());
        }
    }

    private String buildStrings(String[] strings) {
        StringBuilder b = new StringBuilder();
        b.append(strings[0]);
        for (int i = 1; i < strings.length; i++)
            b.append(';').append(strings[i]);
        return b.toString();
    }

    private BuildAuditInfo getAIStoreCtx(StoreContext ctx) {
        StoreSession ss = ctx.getStoreSession();
        HttpServletRequest req = ss.getHttpRequest();
        Attributes attr = ctx.getAttributes();
        String callingHost = ss.getRemoteHostName();
        String callingAET = ss.getCallingAET() != null ? ss.getCallingAET()
                : req != null ? getPreferredUsername(req) : callingHost;
        if (callingAET == null && callingHost == null)
            callingAET = ss.toString();
        String outcome = null != ctx.getException() ? null != ctx.getRejectionNote()
                ? ctx.getRejectionNote().getRejectionNoteCode().getCodeMeaning() + " - " + ctx.getException().getMessage()
                : getOD(ctx.getException()) : null;
        String warning = ctx.getException() == null && null != ctx.getRejectionNote()
                ? ctx.getRejectionNote().getRejectionNoteCode().getCodeMeaning() : null;
        BuildAuditInfo i = new BuildAuditInfo.Builder().callingHost(callingHost).callingAET(callingAET)
                .calledAET(req != null ? req.getRequestURI() : ss.getCalledAET())
                .studyIUIDDateAndAccNum(toStudyUIDDateAccNum(attr))
                .patientIDAndName(toPIDAndName(attr))
                .outcome(outcome).warning(warning).build();
        return i;
    }

    private String getFileName(AuditServiceUtils.EventType et, String callingAET, String calledAET, String studyIUID) {
        return String.valueOf(et) + '-' + callingAET + '-' + calledAET + '-' + studyIUID;
    }

    private String getFailOutcomeDesc(RetrieveContext ctx) {
        return null != ctx.getException()
                ? ctx.getException().getMessage() != null ? ctx.getException().getMessage() : ctx.getException().toString()
                : (ctx.failedSOPInstanceUIDs().length > 0 && (ctx.completed() == 0 && ctx.warning() == 0))
                ? "Unable to perform sub-operations on all instances"
                : (ctx.failedSOPInstanceUIDs().length > 0 && !(ctx.completed() == 0 && ctx.warning() == 0))
                ? "Retrieve of " + ctx.failed() + " objects failed" : null;
    }

    private String getSD(Attributes attr) {
        return attr != null ? attr.getString(Tag.StudyDate) : null;
    }

    private String getAcc(Attributes attr) {
        return attr != null ? attr.getString(Tag.AccessionNumber) : null;
    }

    private String sopCUID(Attributes attrs) {
        return attrs != null ? attrs.getString(Tag.SOPClassUID) : null;
    }

    private String getPreferredUsername(HttpServletRequest req) {
        return req.getAttribute(keycloakClassName) != null
                ? ((RefreshableKeycloakSecurityContext) req.getAttribute(KeycloakSecurityContext.class.getName()))
                .getToken().getPreferredUsername()
                : req.getRemoteAddr();
    }

    private String[] toStudyUIDDateAccNum(Attributes attr) {
        String[] sInfo = new String[3];
        if (attr != null) {
            sInfo[0] = attr.getString(Tag.StudyInstanceUID);
            sInfo[1] = attr.getString(Tag.StudyDate);
            sInfo[2] = attr.getString(Tag.AccessionNumber);
        }
        return sInfo;
    }

    private String[] toPIDAndName(Attributes attr) {
        ArchiveDeviceExtension arcDev = device.getDeviceExtension(ArchiveDeviceExtension.class);
        ShowPatientInfo showPatientInfo = arcDev.showPatientInfoInAuditLog();
        String[] pInfo = new String[2];
        if (attr != null) {
            IDWithIssuer pidWithIssuer = IDWithIssuer.pidOf(attr);
            String pName = attr.getString(Tag.PatientName);
            pInfo[0] = pidWithIssuer != null
                    ? showPatientInfo == ShowPatientInfo.HASH_NAME_AND_ID
                    ? String.valueOf(pidWithIssuer.hashCode())
                    : pidWithIssuer.toString()
                    : arcDev.auditUnknownPatientID();
            pInfo[1] = pName != null && showPatientInfo != ShowPatientInfo.PLAIN_TEXT
                    ? String.valueOf(pName.hashCode())
                    : pName;
        }
        return pInfo;
    }

    private AuditInfo sopInfoForAudit(Attributes attr) {
        return new AuditInfo(
                new BuildAuditInfo.Builder()
                        .sopCUIDAndIUID(
                                new String[]{
                                    attr.getString(Tag.SOPClassUID, Tag.ReferencedSOPClassUID),
                                    attr.getString(Tag.SOPInstanceUID, Tag.ReferencedSOPInstanceUID)})
                        .build());
    }

    private String getOD(Exception e) {
        return e != null ? e.getMessage() : null;
    }

    String getAET(Device device) {
        return AuditMessages.getAET(
                device.getApplicationAETitles().toArray(new String[device.getApplicationAETitles().size()]));
    }

    private void writeSpoolFile(AuditServiceUtils.EventType et, LinkedHashSet<Object> obj) {
        if (obj.isEmpty()) {
            LOG.warn("Attempt to write empty file : " + et);
            return;
        }
        String eventType = String.valueOf(et);
        ArchiveDeviceExtension arcDev = device.getDeviceExtension(ArchiveDeviceExtension.class);
        boolean auditAggregate = arcDev.isAuditAggregate();
        AuditLoggerDeviceExtension ext = device.getDeviceExtension(AuditLoggerDeviceExtension.class);
        for (AuditLogger auditLogger : ext.getAuditLoggers()) {
            if (auditLogger.isInstalled()) {
                Path dir = Paths.get(StringUtils.replaceSystemProperties(arcDev.getAuditSpoolDirectory()),
                        auditLogger.getCommonName().replaceAll(" ", "_"));
                try {
                    Files.createDirectories(dir);
                    Path file = Files.createTempFile(dir, eventType, null);
                    try (SpoolFileWriter writer = new SpoolFileWriter(Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                            StandardOpenOption.APPEND))) {
                        for (Object o : obj)
                            writer.writeLine(o);
                    }
                    if (!auditAggregate)
                        auditAndProcessFile(auditLogger, file);
                } catch (Exception e) {
                    LOG.warn("Failed to write to Audit Spool File - {} ", auditLogger.getCommonName(), e);
                }
            }
        }
    }

    private void writeSpoolFileStoreOrWadoRetrieve(String fileName, Object patStudyInfo, Object instanceInfo) {
        if (patStudyInfo == null && instanceInfo == null) {
            LOG.warn("Attempt to write empty file : " + fileName);
            return;
        }
        ArchiveDeviceExtension arcDev = device.getDeviceExtension(ArchiveDeviceExtension.class);
        boolean auditAggregate = arcDev.isAuditAggregate();
        AuditLoggerDeviceExtension ext = device.getDeviceExtension(AuditLoggerDeviceExtension.class);
        for (AuditLogger auditLogger : ext.getAuditLoggers()) {
            if (auditLogger.isInstalled()) {
                Path dir = Paths.get(StringUtils.replaceSystemProperties(arcDev.getAuditSpoolDirectory()),
                        auditLogger.getCommonName().replaceAll(" ", "_"));
                Path file = dir.resolve(fileName);
                boolean append = Files.exists(file);
                try {
                    if (!append)
                        Files.createDirectories(dir);
                    try (SpoolFileWriter writer = new SpoolFileWriter(Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                            append ? StandardOpenOption.APPEND : StandardOpenOption.CREATE_NEW))) {
                        if (!append) {
                            writer.writeLine(patStudyInfo);
                        }
                        writer.writeLine(instanceInfo);
                    }
                    if (!auditAggregate)
                        auditAndProcessFile(auditLogger, file);
                } catch (Exception e) {
                    LOG.warn("Failed to write to Audit Spool File - {} ", auditLogger.getCommonName(), file, e);
                }
            }
        }
    }

    private LinkedHashSet<Object> getDeletionObjsForSpooling(HashMap<String, HashSet<String>> sopClassMap,
                                                             AuditInfo i) {
        LinkedHashSet<Object> obj = new LinkedHashSet<>();
        obj.add(i);
        for (Map.Entry<String, HashSet<String>> entry : sopClassMap.entrySet()) {
            obj.add(new AuditInfo(new BuildAuditInfo.Builder().sopCUID(entry.getKey())
                    .sopIUID(String.valueOf(entry.getValue().size())).build()));
        }
        return obj;
    }
}
