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
 * Portions created by the Initial Developer are Copyright (C) 2015
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

package org.dcm4chee.arc.query.scp;

import org.dcm4che3.data.Attributes;
import org.dcm4che3.data.Tag;
import org.dcm4che3.net.Association;
import org.dcm4che3.net.Dimse;
import org.dcm4che3.net.Status;
import org.dcm4che3.net.pdu.PresentationContext;
import org.dcm4che3.net.service.BasicQueryTask;
import org.dcm4che3.net.service.DicomServiceException;
import org.dcm4chee.arc.conf.ArchiveAEExtension;
import org.dcm4chee.arc.conf.ArchiveDeviceExtension;
import org.dcm4chee.arc.query.Query;
import org.dcm4chee.arc.query.QueryContext;
import org.hibernate.Transaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * @author Gunter Zeilinger <gunterze@gmail.com>
 * @since Aug 2015
 */
public class ArchiveQueryTask extends BasicQueryTask {
    private static final Logger LOG = LoggerFactory.getLogger(ArchiveQueryTask.class);

    private final Query query;
    private Transaction transaction;

    public ArchiveQueryTask(Association as, PresentationContext pc, Attributes rq, Attributes keys, Query query) {
        super(as, pc, rq, keys);
        this.query = query;
        setOptionalKeysNotSupported(query.isOptionalKeysNotSupported());
    }

    @Override
    public void run() {
        try {
            query.initQuery();
            QueryContext ctx = query.getQueryContext();
            ArchiveAEExtension arcAE = ctx.getArchiveAEExtension();
            ArchiveDeviceExtension arcdev = arcAE.getArchiveDeviceExtension();
            int queryMaxNumberOfResults = arcAE.queryMaxNumberOfResults();
            if (queryMaxNumberOfResults > 0 && !ctx.containsUniqueKey()
                    && query.count() > queryMaxNumberOfResults) {
                throw new DicomServiceException(Status.UnableToProcess, "Request entity too large");
            }
            transaction = query.beginTransaction();
            query.setFetchSize(arcdev.getQueryFetchSize());
            query.executeQuery();
            super.run();
        } catch (DicomServiceException e) {
            writeDimseRSP(e);
        } catch (Exception e) {
            writeDimseRSP(new DicomServiceException(Status.UnableToProcess, e));
        } finally {
            if (transaction != null)
                try {
                    transaction.commit();
                } catch (Exception e) {
                    LOG.warn("Failed to commit transaction:\n{}", e);
                }
            query.close();
        }
    }

    private void writeDimseRSP(DicomServiceException e) {
        int msgId = rq.getInt(Tag.MessageID, -1);
        Attributes rsp = e.mkRSP(Dimse.C_FIND_RSP.commandField(), msgId);
        try {
            as.writeDimseRSP(pc, rsp, null);
        } catch (IOException e1) {
            // handled by Association
        }
    }

    @Override
    protected boolean hasMoreMatches() throws DicomServiceException {
        try {
            return query.hasMoreMatches();
        }  catch (DicomServiceException e) {
            throw e;
        }  catch (Exception e) {
            throw new DicomServiceException(Status.UnableToProcess, e);
        }
    }

    @Override
    protected Attributes nextMatch() throws DicomServiceException {
        try {
            return query.nextMatch();
        }  catch (Exception e) {
            throw new DicomServiceException(Status.UnableToProcess, e);
        }
    }

    @Override
    protected Attributes adjust(Attributes match) {
        if (match == null)
            return null;
        Attributes adjust = query.adjust(match);
        adjust.addSelected(keys, null, Tag.QueryRetrieveLevel);
        switch (query.getQueryContext().getQueryRetrieveLevel()) {
            case STUDY:
                return (adjust.getInt(Tag.NumberOfStudyRelatedInstances, -1) == 0) ? null : adjust;
            case SERIES:
                return (adjust.getInt(Tag.NumberOfSeriesRelatedInstances, -1) == 0) ? null : adjust;
        }
        return adjust;
    }
}
