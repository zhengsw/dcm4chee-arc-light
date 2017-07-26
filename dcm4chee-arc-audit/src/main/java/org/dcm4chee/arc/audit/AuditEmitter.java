package org.dcm4chee.arc.audit;

import org.dcm4che3.audit.*;
import org.dcm4che3.data.UID;
import org.dcm4che3.net.Device;
import org.dcm4che3.net.audit.AuditLogger;
import org.dcm4che3.util.StringUtils;
import org.dcm4chee.arc.conf.ArchiveDeviceExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class AuditEmitter {
    private final Logger LOG = LoggerFactory.getLogger(AuditEmitter.class);
    private final String studyDate = "StudyDate";
    
    @Inject
    private Device device;

    @Inject
    private AuditService auditService;

    void aggregateAuditMessage(AuditLogger auditLogger, Path path) throws IOException {
        AuditServiceUtils.EventType eventType = AuditServiceUtils.EventType.fromFile(path);
        if (path.toFile().length() == 0)
            throw new IOException("Attempt to read from an empty file. ");
        SpoolFileReader readerObj = eventType.eventClass != AuditServiceUtils.EventClass.QUERY
                ? new SpoolFileReader(path) : null;
        Calendar eventTime = getEventTime(path, auditLogger);
        switch (eventType.eventClass) {
            case APPLN_ACTIVITY:
                auditApplicationActivity(auditLogger, readerObj, eventTime, eventType);
                break;
            case CONN_REJECT:
                auditConnectionRejected(auditLogger, readerObj, eventTime, eventType);
                break;
            case STORE_WADOR:
                auditStoreOrWADORetrieve(auditLogger, readerObj, eventTime, eventType);
                break;
            case BEGIN_TRF:
            case RETRIEVE:
            case RETRIEVE_ERR:
                auditRetrieve(auditLogger, readerObj, eventTime, eventType);
                break;
            case DELETE:
            case PERM_DELETE:
                auditDeletion(auditLogger, readerObj, eventTime, eventType);
                break;
            case QUERY:
                auditQuery(auditLogger, path, eventTime, eventType);
                break;
            case HL7:
                auditPatientRecord(auditLogger, readerObj, eventTime, eventType);
                break;
            case PROC_STUDY:
                auditProcedureRecord(auditLogger, readerObj, eventTime, eventType);
                break;
            case PROV_REGISTER:
                auditProvideAndRegister(auditLogger, readerObj, eventTime, eventType);
                break;
            case STGCMT:
                auditStorageCommit(auditLogger, readerObj, eventTime, eventType);
                break;
            case INST_RETRIEVED:
                auditInstancesRetrieved(auditLogger, path, eventType);
                break;
        }
    }

    private void auditApplicationActivity(AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime, AuditServiceUtils.EventType eventType) {
        BuildActiveParticipant ap2 = null;
        AuditInfo archiveInfo = new AuditInfo(readerObj.getMainInfo());
        if (!readerObj.getInstanceLines().isEmpty()) {
            AuditInfo callerInfo = new AuditInfo(readerObj.getInstanceLines().iterator().next());
            ap2 = new BuildActiveParticipant.Builder(
                    callerInfo.getField(AuditInfo.CALLING_AET), callerInfo.getField(AuditInfo.CALLING_HOST)).
                    requester(eventType.isSource).roleIDCode(eventType.source).build();
        }
        EventIdentification ei = getEI(eventType, null, eventTime);
        BuildActiveParticipant ap1 = new BuildActiveParticipant.Builder(archiveInfo.getField(AuditInfo.CALLED_AET),
                getLocalHostName(auditLogger)).altUserID(AuditLogger.processID()).requester(eventType.isDest)
                .roleIDCode(eventType.destination).build();
        emitAuditMessage(ei, !readerObj.getInstanceLines().isEmpty() ? getApList(ap1, ap2) : getApList(ap1), null, auditLogger);
    }

    private void auditDeletion(AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime, AuditServiceUtils.EventType eventType) {
        AuditInfo dI = new AuditInfo(readerObj.getMainInfo());
        EventIdentification ei = getCustomEI(eventType, dI.getField(AuditInfo.OUTCOME),
                dI.getField(AuditInfo.WARNING), eventTime);
        BuildActiveParticipant ap1 = null;
        if (eventType.isSource) {
            ap1 = new BuildActiveParticipant.Builder(
                    dI.getField(AuditInfo.CALLING_AET), dI.getField(AuditInfo.CALLING_HOST))
                    .requester(eventType.isSource).build();
        }
        BuildActiveParticipant ap2 = new BuildActiveParticipant.Builder(
                eventType.isSource ? dI.getField(AuditInfo.CALLED_AET) : auditService.getAET(device),
                getLocalHostName(auditLogger)).altUserID(AuditLogger.processID())
                .requester(eventType.isDest).build();
        ParticipantObjectContainsStudy pocs = getPocs(dI.getField(AuditInfo.STUDY_UID));
        BuildParticipantObjectDescription desc = new BuildParticipantObjectDescription.Builder(
                getSopClasses(readerObj.getInstanceLines()), pocs)
                .acc(getAccessions(dI.getField(AuditInfo.ACC_NUM))).build();
        BuildParticipantObjectIdentification poi1 = new BuildParticipantObjectIdentification.Builder(
                dI.getField(AuditInfo.STUDY_UID), AuditMessages.ParticipantObjectIDTypeCode.StudyInstanceUID,
                AuditMessages.ParticipantObjectTypeCode.SystemObject,AuditMessages.ParticipantObjectTypeCodeRole.Report)
                .desc(getPODesc(desc)).detail(getPod(studyDate, dI.getField(AuditInfo.STUDY_DATE))).build();
        BuildParticipantObjectIdentification poi2 = new BuildParticipantObjectIdentification.Builder(
                dI.getField(AuditInfo.P_ID), AuditMessages.ParticipantObjectIDTypeCode.PatientNumber,
                AuditMessages.ParticipantObjectTypeCode.Person, AuditMessages.ParticipantObjectTypeCodeRole.Patient)
                .name(dI.getField(AuditInfo.P_NAME)).build();
        emitAuditMessage(ei, eventType.isSource ? getApList(ap1, ap2) : getApList(ap2),
                getPoiList(poi1, poi2), auditLogger);
    }

    private void auditInstancesRetrieved(AuditLogger auditLogger, Path path, AuditServiceUtils.EventType eventType)
            throws IOException {
        SpoolFileReader reader = new SpoolFileReader(path);
        AuditInfo i = new AuditInfo(reader.getMainInfo());
        EventIdentification ei = getEI(eventType, i.getField(AuditInfo.OUTCOME), getEventTime(path, auditLogger));
        BuildActiveParticipant ap1 = new BuildActiveParticipant.Builder(
                i.getField(AuditInfo.CALLING_AET),
                i.getField(AuditInfo.CALLING_HOST))
                .altUserID(i.getField(AuditInfo.MOVEAET))
                .requester(eventType.isSource)
                .build();
        BuildActiveParticipant ap2 = new BuildActiveParticipant.Builder(
                i.getField(AuditInfo.CALLED_AET),
                i.getField(AuditInfo.CALLED_HOST))
                .requester(eventType.isDest)
                .build();
        BuildActiveParticipant ap3 = new BuildActiveParticipant.Builder(
                i.getField(AuditInfo.DEST_AET),
                i.getField(AuditInfo.DEST_NAP_ID))
                .requester(eventType.isOther)
                .build();
        BuildParticipantObjectIdentification studyPOI = new BuildParticipantObjectIdentification.Builder(
                i.getField(AuditInfo.STUDY_UID), AuditMessages.ParticipantObjectIDTypeCode.StudyInstanceUID,
                AuditMessages.ParticipantObjectTypeCode.SystemObject, AuditMessages.ParticipantObjectTypeCodeRole.Report)
                .build();
        emitAuditMessage(ei, getApList(ap1, ap2, ap3), getPoiList(studyPOI), auditLogger);
    }

    private void auditConnectionRejected(AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime, AuditServiceUtils.EventType eventType) {
        AuditInfo crI = new AuditInfo(readerObj.getMainInfo());
        EventIdentification ei = getEI(eventType, crI.getField(AuditInfo.OUTCOME), eventTime);
        BuildActiveParticipant ap1 = new BuildActiveParticipant.Builder(auditService.getAET(device),
                crI.getField(AuditInfo.CALLED_HOST)).altUserID(AuditLogger.processID()).requester(false).build();
        String userID, napID;
        userID = napID = crI.getField(AuditInfo.CALLING_HOST);
        BuildActiveParticipant ap2 = new BuildActiveParticipant.Builder(userID, napID).requester(true).build();
        BuildParticipantObjectIdentification poi = new BuildParticipantObjectIdentification.Builder(
                crI.getField(AuditInfo.CALLING_HOST), AuditMessages.ParticipantObjectIDTypeCode.NodeID,
                AuditMessages.ParticipantObjectTypeCode.SystemObject, null).build();
        emitAuditMessage(ei, getApList(ap1, ap2), getPoiList(poi), auditLogger);
    }

    private void auditQuery(
            AuditLogger auditLogger, Path file, Calendar eventTime, AuditServiceUtils.EventType eventType) throws IOException {
        AuditInfo qrI;
        List<ActiveParticipant> apList;
        List<ParticipantObjectIdentification> poiList;
        EventIdentification ei = getEI(eventType, null, eventTime);
        try (InputStream in = new BufferedInputStream(Files.newInputStream(file))) {
            qrI = new AuditInfo(new DataInputStream(in).readUTF());
            BuildActiveParticipant ap1 = new BuildActiveParticipant.Builder(qrI.getField(AuditInfo.CALLING_AET),
                    qrI.getField(AuditInfo.CALLING_HOST)).requester(eventType.isSource).roleIDCode(eventType.source)
                    .build();
            BuildActiveParticipant ap2 = new BuildActiveParticipant.Builder(qrI.getField(AuditInfo.CALLED_AET),
                    getLocalHostName(auditLogger)).altUserID(AuditLogger.processID())
                    .requester(eventType.isDest).roleIDCode(eventType.destination).build();
            apList = getApList(ap1, ap2);
            BuildParticipantObjectIdentification poi;
            if (eventType == AuditServiceUtils.EventType.QUERY_QIDO) {
                poi = new BuildParticipantObjectIdentification.Builder(
                        qrI.getField(AuditInfo.Q_POID), AuditMessages.ParticipantObjectIDTypeCode.QIDO_QUERY,
                        AuditMessages.ParticipantObjectTypeCode.SystemObject,
                        AuditMessages.ParticipantObjectTypeCodeRole.Query)
                        .query(qrI.getField(AuditInfo.Q_STRING).getBytes())
                        .detail(getPod("QueryEncoding", String.valueOf(StandardCharsets.UTF_8))).build();
            }
            else {
                byte[] buffer = new byte[(int) Files.size(file)];
                int len = in.read(buffer);
                byte[] data;
                if (len != -1) {
                    data = new byte[len];
                    System.arraycopy(buffer, 0, data, 0, len);
                }
                else {
                    data = new byte[0];
                }
                poi = new BuildParticipantObjectIdentification.Builder(
                        qrI.getField(AuditInfo.Q_POID), AuditMessages.ParticipantObjectIDTypeCode.SOPClassUID,
                        AuditMessages.ParticipantObjectTypeCode.SystemObject,
                        AuditMessages.ParticipantObjectTypeCodeRole.Report).query(data)
                        .detail(getPod("TransferSyntax", UID.ImplicitVRLittleEndian)).build();
            }
            poiList = getPoiList(poi);
        }
        emitAuditMessage(ei, apList, poiList, auditLogger);
    }

    private void auditStoreOrWADORetrieve(AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime,
                                          AuditServiceUtils.EventType eventType) {
        HashSet<String> mppsUIDs = new HashSet<>();
        HashMap<String, HashSet<String>> sopClassMap = new HashMap<>();
        AuditInfo i = new AuditInfo(readerObj.getMainInfo());
        for (String line : readerObj.getInstanceLines()) {
            AuditInfo iI = new AuditInfo(line);
            auditService.buildSOPClassMap(sopClassMap, iI.getField(AuditInfo.SOP_CUID), iI.getField(AuditInfo.SOP_IUID));
            mppsUIDs.add(iI.getField(AuditInfo.MPPS_UID));
        }
        mppsUIDs.remove(" ");
        EventIdentification ei = getEI(eventType, i.getField(AuditInfo.OUTCOME), eventTime);
        BuildActiveParticipant ap1 = new BuildActiveParticipant.Builder(
                i.getField(AuditInfo.CALLING_AET),
                i.getField(AuditInfo.CALLING_HOST)).requester(eventType.isSource)
                .roleIDCode(eventType.source).build();
        BuildActiveParticipant ap2 = new BuildActiveParticipant.Builder(
                i.getField(AuditInfo.CALLED_AET), getLocalHostName(auditLogger))
                .altUserID(AuditLogger.processID()).requester(eventType.isDest).roleIDCode(eventType.destination).build();
        HashSet<SOPClass> sopC = new HashSet<>();
        for (Map.Entry<String, HashSet<String>> entry : sopClassMap.entrySet())
            sopC.add(getSOPC(null, entry.getKey(), entry.getValue().size()));
        ParticipantObjectContainsStudy pocs = getPocs(i.getField(AuditInfo.STUDY_UID));
        BuildParticipantObjectDescription desc = new BuildParticipantObjectDescription.Builder(sopC, pocs)
                .acc(getAccessions(i.getField(AuditInfo.ACC_NUM)))
                .mpps(AuditMessages.getMPPS(mppsUIDs.toArray(new String[mppsUIDs.size()]))).build();
        String lifecycle = (eventType == AuditServiceUtils.EventType.STORE_CREA
                || eventType == AuditServiceUtils.EventType.STORE_UPDT)
                ? AuditMessages.ParticipantObjectDataLifeCycle.OriginationCreation : null;
        BuildParticipantObjectIdentification poi1 = new BuildParticipantObjectIdentification.Builder(
                i.getField(AuditInfo.STUDY_UID),
                AuditMessages.ParticipantObjectIDTypeCode.StudyInstanceUID,
                AuditMessages.ParticipantObjectTypeCode.SystemObject, AuditMessages.ParticipantObjectTypeCodeRole.Report)
                .desc(getPODesc(desc)).detail(getPod(studyDate, i.getField(AuditInfo.STUDY_DATE))).lifeCycle(lifecycle).build();
        BuildParticipantObjectIdentification poi2 = new BuildParticipantObjectIdentification.Builder(
                i.getField(AuditInfo.P_ID),
                AuditMessages.ParticipantObjectIDTypeCode.PatientNumber,
                AuditMessages.ParticipantObjectTypeCode.Person, AuditMessages.ParticipantObjectTypeCodeRole.Patient)
                .name(i.getField(AuditInfo.P_NAME)).build();
        emitAuditMessage(ei, getApList(ap1, ap2), getPoiList(poi1, poi2), auditLogger);
    }

    private void auditRetrieve(AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime, AuditServiceUtils.EventType eventType) {
        AuditInfo ri = new AuditInfo(readerObj.getMainInfo());
        EventIdentification ei = getCustomEI(eventType, ri.getField(AuditInfo.OUTCOME),
                ri.getField(AuditInfo.WARNING), eventTime);
        BuildActiveParticipant ap1 = new BuildActiveParticipant.Builder(ri.getField(AuditInfo.CALLED_AET),
                getLocalHostName(auditLogger)).altUserID(AuditLogger.processID()).requester(eventType.isSource)
                .roleIDCode(eventType.source).build();
        BuildActiveParticipant ap2 = new BuildActiveParticipant.Builder(ri.getField(AuditInfo.DEST_AET),
                ri.getField(AuditInfo.DEST_NAP_ID)).requester(eventType.isDest).roleIDCode(eventType.destination).build();
        BuildActiveParticipant ap3 = null;
        if (eventType.isOther) {
            ap3 = new BuildActiveParticipant.Builder(ri.getField(AuditInfo.MOVEAET),
                    ri.getField(AuditInfo.CALLING_HOST)).requester(eventType.isOther).build();
        }
        HashMap<String, AccessionNumSopClassInfo> study_accNumSOPClassInfo = new HashMap<>();
        String pID = device.getDeviceExtension(ArchiveDeviceExtension.class).auditUnknownPatientID();
        String pName = null;
        String studyDt = null;
        for (String line : readerObj.getInstanceLines()) {
            AuditInfo rInfo = new AuditInfo(line);
            String studyInstanceUID = rInfo.getField(AuditInfo.STUDY_UID);
            AccessionNumSopClassInfo accNumSopClassInfo = study_accNumSOPClassInfo.get(studyInstanceUID);
            if (accNumSopClassInfo == null) {
                accNumSopClassInfo = new AccessionNumSopClassInfo(
                        rInfo.getField(AuditInfo.ACC_NUM));
                study_accNumSOPClassInfo.put(studyInstanceUID, accNumSopClassInfo);
            }
            accNumSopClassInfo.addSOPInstance(rInfo);
            study_accNumSOPClassInfo.put(studyInstanceUID, accNumSopClassInfo);
            pID = rInfo.getField(AuditInfo.P_ID);
            pName = rInfo.getField(AuditInfo.P_NAME);
            studyDt = rInfo.getField(AuditInfo.STUDY_DATE);
        }
        List<BuildParticipantObjectIdentification> pois = new ArrayList<>();
        for (Map.Entry<String, AccessionNumSopClassInfo> entry : study_accNumSOPClassInfo.entrySet()) {
            HashSet<SOPClass> sopC = new HashSet<>();
            for (Map.Entry<String, HashSet<String>> sopClassMap : entry.getValue().getSopClassMap().entrySet()) {
                if (ri.getField(AuditInfo.FAILED_IUID_SHOW) != null)
                    sopC.add(getSOPC(sopClassMap.getValue(), sopClassMap.getKey(), sopClassMap.getValue().size()));
                else
                    sopC.add(getSOPC(null, sopClassMap.getKey(), sopClassMap.getValue().size()));
            }
            BuildParticipantObjectDescription desc = new BuildParticipantObjectDescription.Builder(sopC, getPocs(entry.getKey()))
                    .acc(getAccessions(entry.getValue().getAccNum())).build();
            BuildParticipantObjectIdentification poi = new BuildParticipantObjectIdentification.Builder(
                    entry.getKey(), AuditMessages.ParticipantObjectIDTypeCode.StudyInstanceUID,
                    AuditMessages.ParticipantObjectTypeCode.SystemObject, AuditMessages.ParticipantObjectTypeCodeRole.Report)
                    .desc(getPODesc(desc)).detail(getPod(studyDate, studyDt)).build();
            pois.add(poi);
        }
        BuildParticipantObjectIdentification poiPatient = new BuildParticipantObjectIdentification.Builder(
                pID, AuditMessages.ParticipantObjectIDTypeCode.PatientNumber,
                AuditMessages.ParticipantObjectTypeCode.Person, AuditMessages.ParticipantObjectTypeCodeRole.Patient)
                .name(pName).build();
        pois.add(poiPatient);
        emitAuditMessage(ei, eventType.isOther ? getApList(ap1, ap2, ap3) : getApList(ap1, ap2),
                getPoiList(pois.toArray(new BuildParticipantObjectIdentification[pois.size()])), auditLogger);
    }

    private void auditPatientRecord(
            AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime, AuditServiceUtils.EventType et) {
        AuditInfo hl7I = new AuditInfo(readerObj.getMainInfo());
        EventIdentification ei = getEI(et, hl7I.getField(AuditInfo.OUTCOME), eventTime);
        BuildActiveParticipant ap1 = null;
        if (et.isSource)
            ap1 = new BuildActiveParticipant.Builder(hl7I.getField(AuditInfo.CALLING_AET),
                    hl7I.getField(AuditInfo.CALLING_HOST)).requester(et.isSource).roleIDCode(et.source).build();
        BuildActiveParticipant ap2 = new BuildActiveParticipant.Builder(
                et.isSource ? hl7I.getField(AuditInfo.CALLED_AET) : auditService.getAET(device),
                getLocalHostName(auditLogger)).altUserID(AuditLogger.processID()).requester(et.isDest)
                .roleIDCode(et.destination).build();
        BuildParticipantObjectIdentification poi = new BuildParticipantObjectIdentification.Builder(
                hl7I.getField(AuditInfo.P_ID), AuditMessages.ParticipantObjectIDTypeCode.PatientNumber,
                AuditMessages.ParticipantObjectTypeCode.Person, AuditMessages.ParticipantObjectTypeCodeRole.Patient)
                .name(hl7I.getField(AuditInfo.P_NAME)).detail(getPod("HL7MessageType", hl7I.getField(AuditInfo.HL7_MESSAGE_TYPE))).build();
        emitAuditMessage(ei, et.isSource ? getApList(ap1, ap2) : getApList(ap2), getPoiList(poi), auditLogger);
    }

    private void auditProcedureRecord(AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime, AuditServiceUtils.EventType et) {
        AuditInfo prI = new AuditInfo(readerObj.getMainInfo());
        EventIdentification ei = getEI(et, prI.getField(AuditInfo.OUTCOME), eventTime);
        BuildActiveParticipant ap1 = new BuildActiveParticipant.Builder(prI.getField(AuditInfo.CALLING_AET),
                prI.getField(AuditInfo.CALLING_HOST)).requester(et.isSource).build();
        BuildActiveParticipant ap2 = new BuildActiveParticipant.Builder(prI.getField(AuditInfo.CALLED_AET),
                getLocalHostName(auditLogger)).altUserID(AuditLogger.processID()).requester(et.isDest).build();
        ParticipantObjectContainsStudy pocs = getPocs(prI.getField(AuditInfo.STUDY_UID));
        BuildParticipantObjectDescription desc = new BuildParticipantObjectDescription.Builder(null, pocs)
                .acc(getAccessions(prI.getField(AuditInfo.ACC_NUM))).build();
        BuildParticipantObjectIdentification poi1 = new BuildParticipantObjectIdentification.Builder(
                prI.getField(AuditInfo.STUDY_UID), AuditMessages.ParticipantObjectIDTypeCode.StudyInstanceUID,
                AuditMessages.ParticipantObjectTypeCode.SystemObject, AuditMessages.ParticipantObjectTypeCodeRole.Report)
                .desc(getPODesc(desc)).detail(getPod(studyDate, prI.getField(AuditInfo.STUDY_DATE))).build();
        BuildParticipantObjectIdentification poi2 = new BuildParticipantObjectIdentification.Builder(
                prI.getField(AuditInfo.P_ID), AuditMessages.ParticipantObjectIDTypeCode.PatientNumber,
                AuditMessages.ParticipantObjectTypeCode.Person, AuditMessages.ParticipantObjectTypeCodeRole.Patient)
                .name(prI.getField(AuditInfo.P_NAME)).build();
        emitAuditMessage(ei, getApList(ap1, ap2), getPoiList(poi1, poi2), auditLogger);
    }

    private void auditProvideAndRegister(AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime, AuditServiceUtils.EventType et) {
        AuditInfo ai = new AuditInfo(readerObj.getMainInfo());
        EventIdentification ei = getEI(et, ai.getField(AuditInfo.OUTCOME), eventTime);
        BuildActiveParticipant apSource = new BuildActiveParticipant.Builder(ai.getField(AuditInfo.CALLING_AET),
                getLocalHostName(auditLogger)).altUserID(AuditLogger.processID()).requester(et.isSource).roleIDCode(et.source).build();
        BuildActiveParticipant apDest = new BuildActiveParticipant.Builder(ai.getField(AuditInfo.CALLED_AET),
                ai.getField(AuditInfo.CALLED_HOST)).requester(et.isDest).roleIDCode(et.destination).build();
        BuildParticipantObjectIdentification poiPatient = new BuildParticipantObjectIdentification.Builder(
                ai.getField(AuditInfo.P_ID), AuditMessages.ParticipantObjectIDTypeCode.PatientNumber,
                AuditMessages.ParticipantObjectTypeCode.Person, AuditMessages.ParticipantObjectTypeCodeRole.Patient)
                .build();
        BuildParticipantObjectIdentification poiSubmissionSet = new BuildParticipantObjectIdentification.Builder(
                ai.getField(AuditInfo.SUBMISSION_SET_UID), AuditMessages.ParticipantObjectIDTypeCode.IHE_XDS_METADATA,
                AuditMessages.ParticipantObjectTypeCode.SystemObject, AuditMessages.ParticipantObjectTypeCodeRole.Job)
                .build();
        emitAuditMessage(ei, getApList(apSource, apDest), getPoiList(poiPatient, poiSubmissionSet), auditLogger);
    }

    private void auditStorageCommit(AuditLogger auditLogger, SpoolFileReader readerObj, Calendar eventTime, AuditServiceUtils.EventType et) {
        AuditInfo stgCmtI = new AuditInfo(readerObj.getMainInfo());
        EventIdentification ei = getEI(et, stgCmtI.getField(AuditInfo.OUTCOME), eventTime);
        BuildActiveParticipant apDest = new BuildActiveParticipant.Builder(stgCmtI.getField(AuditInfo.CALLED_AET),
                getLocalHostName(auditLogger)).altUserID(AuditLogger.processID()).requester(et.isDest)
                .roleIDCode(et.destination).build();
        BuildActiveParticipant apSource = new BuildActiveParticipant.Builder(stgCmtI.getField(AuditInfo.CALLING_AET),
                stgCmtI.getField(AuditInfo.CALLING_HOST)).requester(et.isSource).roleIDCode(et.source).build();
        BuildParticipantObjectIdentification poiPat = new BuildParticipantObjectIdentification.Builder(
                stgCmtI.getField(AuditInfo.P_ID), AuditMessages.ParticipantObjectIDTypeCode.PatientNumber,
                AuditMessages.ParticipantObjectTypeCode.Person, AuditMessages.ParticipantObjectTypeCodeRole.Patient)
                .name(stgCmtI.getField(AuditInfo.P_NAME)).build();
        String[] studyUIDs = StringUtils.split(stgCmtI.getField(AuditInfo.STUDY_UID), ';');
        ParticipantObjectContainsStudy pocs = getPocs(studyUIDs);
        HashMap<String, HashSet<String>> sopClassMap = new HashMap<>();
        for (String line : readerObj.getInstanceLines()) {
            AuditInfo ii = new AuditInfo(line);
            auditService.buildSOPClassMap(sopClassMap, ii.getField(AuditInfo.SOP_CUID), ii.getField(AuditInfo.SOP_IUID));
        }
        HashSet<SOPClass> sopC = new HashSet<>();
        if (studyUIDs.length>1 || stgCmtI.getField(AuditInfo.OUTCOME) != null)
            for (Map.Entry<String, HashSet<String>> entry : sopClassMap.entrySet())
                sopC.add(getSOPC(entry.getValue(), entry.getKey(), entry.getValue().size()));
        else
            for (Map.Entry<String, HashSet<String>> entry : sopClassMap.entrySet())
                sopC.add(getSOPC(null, entry.getKey(), entry.getValue().size()));
        BuildParticipantObjectDescription poDesc = new BuildParticipantObjectDescription.Builder(sopC, pocs).build();
        BuildParticipantObjectIdentification poiStudy = new BuildParticipantObjectIdentification.Builder(studyUIDs[0],
                AuditMessages.ParticipantObjectIDTypeCode.StudyInstanceUID,
                AuditMessages.ParticipantObjectTypeCode.SystemObject, AuditMessages.ParticipantObjectTypeCodeRole.Report)
                .desc(getPODesc(poDesc)).lifeCycle(AuditMessages.ParticipantObjectDataLifeCycle.Verification).build();
        emitAuditMessage(ei, getApList(apSource, apDest), getPoiList(poiStudy, poiPat), auditLogger);
    }

    private Calendar getEventTime(Path path, AuditLogger auditLogger){
        Calendar eventTime = auditLogger.timeStamp();
        try {
            eventTime.setTimeInMillis(Files.getLastModifiedTime(path).toMillis());
        } catch (Exception e) {
            LOG.warn("Failed to get Last Modified Time of Audit Spool File - {} ", auditLogger.getCommonName(), path, e);
        }
        return eventTime;
    }

    private String getLocalHostName(AuditLogger log) {
        return log.getConnections().get(0).getHostname();
    }

    private List<ActiveParticipant> getApList(BuildActiveParticipant... aps) {
        return AuditMessages.getApList(aps);
    }

    private List<ParticipantObjectIdentification> getPoiList(BuildParticipantObjectIdentification... pois) {
        return AuditMessages.getPoiList(pois);
    }

    private void emitAuditMessage(EventIdentification ei, List<ActiveParticipant> apList,
                                  List<ParticipantObjectIdentification> poiList, AuditLogger log) {
        AuditMessage msg = AuditMessages.createMessage(ei, apList, poiList);
        msg.getAuditSourceIdentification().add(log.createAuditSourceIdentification());
        try {
            log.write(log.timeStamp(), msg);
        } catch (Exception e) {
            LOG.warn("Failed to emit audit message", log.getCommonName(), e);
        }
    }

    private String getEOI(String outcomeDesc) {
        return outcomeDesc != null ? AuditMessages.EventOutcomeIndicator.MinorFailure : AuditMessages.EventOutcomeIndicator.Success;
    }

    private EventIdentification getEI(AuditServiceUtils.EventType et, String desc, Calendar t) {
        BuildEventIdentification ei =  new BuildEventIdentification.Builder(
                et.eventID, et.eventActionCode, t, getEOI(desc)).outcomeDesc(desc).eventTypeCode(et.eventTypeCode).build();
        return AuditMessages.getEI(ei);
    }

    private EventIdentification getCustomEI(AuditServiceUtils.EventType et, String failureDesc, String warningDesc, Calendar t) {
        if (failureDesc != null)
            return getEI(et, failureDesc, t);
        else {
            BuildEventIdentification ei = new BuildEventIdentification.Builder(
                    et.eventID, et.eventActionCode, t, AuditMessages.EventOutcomeIndicator.Success)
                    .outcomeDesc(warningDesc).build();
            return AuditMessages.getEI(ei);
        }
    }

    private ParticipantObjectDetail getPod(String type, String value) {
        return value != null ? AuditMessages.createParticipantObjectDetail(type, value.getBytes()) : null;
    }

    private ParticipantObjectContainsStudy getPocs(String... studyUIDs) {
        return AuditMessages.getPocs(studyUIDs);
    }

    private ParticipantObjectDescription getPODesc(BuildParticipantObjectDescription desc) {
        return AuditMessages.getPODesc(desc);
    }

    private HashSet<Accession> getAccessions(String accNum) {
        return AuditMessages.getAccessions(accNum);
    }

    private HashSet<SOPClass> getSopClasses(HashSet<String> instanceLines) {
        HashSet<SOPClass> sopC = new HashSet<>();
        for (String line : instanceLines) {
            AuditInfo ii = new AuditInfo(line);
            sopC.add(getSOPC(null, ii.getField(AuditInfo.SOP_CUID),
                    Integer.parseInt(ii.getField(AuditInfo.SOP_IUID))));
        }
        return sopC;
    }

    private SOPClass getSOPC(HashSet<String> instances, String uid, Integer numI) {
        return AuditMessages.getSOPC(instances, uid, numI);
    }
    
    
}
