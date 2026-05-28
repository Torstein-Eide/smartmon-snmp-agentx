// snmp_sata_mib.cpp — SATA attribute and self-test table handlers

#include "snmp_sata_mib.h"
#include "snmp_mib_helpers.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

// ---------------------------------------------------------------------------
// SATA table metadata scalar handlers
// ---------------------------------------------------------------------------

TABLE_ROW_COUNT_HANDLER(sata_info_row_count_handler,      sata_info)

TABLE_ROW_COUNT_HANDLER(sata_health_row_count_handler,    sata_health)
TABLE_LAST_CHANGE_HANDLER(sata_health_last_change_handler, ts_sata_health)

TABLE_ROW_COUNT_HANDLER(sata_attr_row_count_handler,      sata_attrs)
TABLE_LAST_CHANGE_HANDLER(sata_attr_last_change_handler,  ts_sata_attr)

TABLE_ROW_COUNT_HANDLER(sata_el_row_count_handler,        sata_error_log)
TABLE_LAST_CHANGE_HANDLER(sata_el_last_change_handler,    ts_sata_error_log)

TABLE_ROW_COUNT_HANDLER(sata_st_row_count_handler,        sata_selftests)
TABLE_LAST_CHANGE_HANDLER(sata_st_last_change_handler,    ts_sata_selftest)

TABLE_ROW_COUNT_HANDLER(sata_errcmd_row_count_handler,    sata_error_cmds)
TABLE_LAST_CHANGE_HANDLER(sata_errcmd_last_change_handler, ts_sata_error_cmd)

TABLE_ROW_COUNT_HANDLER(sata_erc_row_count_handler,       sata_erc)
TABLE_LAST_CHANGE_HANDLER(sata_erc_last_change_handler,   ts_sata_erc)

TABLE_ROW_COUNT_HANDLER(sata_phy_event_row_count_handler,     sata_phy_events)
TABLE_LAST_CHANGE_HANDLER(sata_phy_event_last_change_handler, ts_sata_phy_event)

TABLE_ROW_COUNT_HANDLER(sata_selective_row_count_handler,     sata_selective_tests)
TABLE_LAST_CHANGE_HANDLER(sata_selective_last_change_handler, ts_sata_selective_test)

TABLE_ROW_COUNT_HANDLER(sata_logdir_row_count_handler,    sata_log_dir)
TABLE_LAST_CHANGE_HANDLER(sata_logdir_last_change_handler, ts_sata_log_dir)

TABLE_ROW_COUNT_HANDLER(sata_devstat_row_count_handler,    sata_dev_stats)
TABLE_LAST_CHANGE_HANDLER(sata_devstat_last_change_handler, ts_sata_dev_stat)

// Convert raw ATA flags byte to ASN.1 BITS byte.
// Raw bit i → ASN.1 bit i → MSBit-first octet position (7-i).
static uint8_t ata_flags_to_bits(uint8_t raw) {
    uint8_t b = 0;
    for (int i = 0; i < 6; i++)
        if (raw & (1 << i)) b |= (uint8_t)(0x80u >> i);
    return b;
}

// ---------------------------------------------------------------------------
// SATA info table
// INDEX { smartmonDeviceIndex }
// col 1  = ataVersion (SmartmonAtaVersion)
// col 2  = sataVersion (SmartmonSataVersion)
// col 3  = rotationRate
// col 4  = formFactor (SmartmonAtaFormFactor)
// col 5  = logicalBlockSize
// col 6  = physicalBlockSize
// col 7  = userCapacityBytes
// col 8  = inSmartctlDatabase (TruthValue)
// col 9  = smartAvailable (TruthValue)
// col 10 = smartEnabled (TruthValue)
// col 11 = trimSupported (TruthValue)
// col 12 = userCapacityBlocks
// col 13 = ataVersionMajor
// col 14 = ataVersionMinor
// col 15 = ifSpeedMaxValue
// col 16 = ifSpeedCurrentValue
// col 17 = apmEnabled (TruthValue)
// col 18 = apmLevel
// col 19 = readLookaheadEnabled (TruthValue)
// col 20 = writeCacheEnabled (TruthValue)
// col 21 = securityState
// col 22 = securityEnabled (TruthValue)
// col 23 = securityFrozen (TruthValue)
// col 24 = attrRevision
// col 25 = offlineCollectionCompletionSecs
// col 26 = selfTestPollingShortMinutes
// col 27 = selfTestPollingExtendedMinutes
// col 28 = selfTestPollingConveyanceMinutes
// col 29 = capabilitySelfTestsSupported (TruthValue)
// col 30 = capabilityConveyanceSupported (TruthValue)
// col 31 = capabilitySelectiveSupported (TruthValue)
// col 32 = capabilityErrorLoggingSupported (TruthValue)
// col 33 = capabilityGpLoggingSupported (TruthValue)
// col 34 = sctErrorRecoverySupported (TruthValue)
// col 35 = sctFeatureControlSupported (TruthValue)
// col 36 = sctDataTableSupported (TruthValue)
// col 37 = capabilityExecOfflineImmediate (TruthValue)
// col 38 = capabilityOfflineAbortedOnCmd (TruthValue)
// col 39 = capabilityOfflineSurfaceScan (TruthValue)
// col 40 = errorLogRevision
// col 41 = errorLogSectors
// col 42 = selfTestLogRevision
// col 43 = selfTestLogSectors
// col 44 = pendingDefectsSize
// col 45 = capabilityAttrAutosave (TruthValue)
// col 46 = sctHistOpLimitMin
// col 47 = sctHistOpLimitMax
// col 48 = sctHistLimitMin
// col 49 = sctHistLimitMax
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_info_get_next(void **loop_ctx, void **data_ctx,
                   netsnmp_variable_list *put_idx,
                   netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_info.size()) return nullptr;
    CacheSataInfoRow &row = g_cache.sata_info[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_info_handler(netsnmp_mib_handler *,
                  netsnmp_handler_registration *,
                  netsnmp_agent_request_info *reqinfo,
                  netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;

    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataInfoRow *row =
            (CacheSataInfoRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;

        switch (tinfo->colnum) {
        case 1:  { long v = (long)row->ata_version;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 2:  { long v = (long)row->sata_version;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 3:  { u_long v = row->rotation_rate;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 4:  { long v = (long)row->form_factor;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 5:  { u_long v = row->logical_block_size;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 6:  { u_long v = row->physical_block_size;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 7:  set_counter64(req, row->user_capacity_bytes); break;
        case 8:  { long v = row->in_smartctl_db ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 9:  { long v = row->smart_available ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 10: { long v = row->smart_enabled ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 11: { long v = row->trim_supported ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 12: set_counter64(req, row->user_capacity_blocks); break;
        case 13: { u_long v = row->ata_version_major;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 14: { u_long v = row->ata_version_minor;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 15: { u_long v = row->if_speed_max_mbps;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 16: { u_long v = row->if_speed_current_mbps;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 17: { long v = row->apm_enabled ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 18: { long v = (long)row->apm_level;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 19: { long v = row->read_lookahead_enabled ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 20: { long v = row->write_cache_enabled ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 21: { u_long v = row->security_state;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 22: { long v = row->security_enabled ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 23: { long v = row->security_frozen ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 24: { u_long v = row->attr_revision;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 25: { u_long v = row->offline_completion_secs;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 26: { u_long v = row->polling_short_min;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 27: { u_long v = row->polling_ext_min;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 28: { u_long v = row->polling_conv_min;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 29: { long v = row->cap_selftests ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 30: { long v = row->cap_conveyance ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 31: { long v = row->cap_selective ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 32: { long v = row->cap_error_logging ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 33: { long v = row->cap_gp_logging ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 34: { long v = row->sct_error_recovery ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 35: { long v = row->sct_feature_control ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 36: { long v = row->sct_data_table ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 37: { long v = row->cap_exec_offline_immediate ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 38: { long v = row->cap_offline_aborted_on_cmd ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 39: { long v = row->cap_offline_surface_scan ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 40: { u_long v = row->error_log_revision;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 41: { u_long v = row->error_log_sectors;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 42: { u_long v = row->selftest_log_revision;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 43: { u_long v = row->selftest_log_sectors;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 44: { u_long v = row->pending_defects_size;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 45: { long v = row->cap_attr_autosave ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 46: { long v = row->sct_hist_op_limit_min;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 47: { long v = row->sct_hist_op_limit_max;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 48: { long v = row->sct_hist_limit_min;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 49: { long v = row->sct_hist_limit_max;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA health table  (ATA/SATA SMART live-state objects, 5-minute polling)
// INDEX { smartmonDeviceIndex }
// col 1  = healthOverallStatus
// col 2  = offlineCollectionStatusValue
// col 3  = selfTestExecutionStatusValue
// col 4  = powerCycles
// col 5  = powerOnHours
// col 6  = errorLogCount
// col 7  = pendingDefectsCount
// col 8  = selfTestLogCount
// col 9  = selfTestLogErrTotal
// col 10 = selfTestLogErrOutdated
// col 11 = sctStatusFormatVersion
// col 12 = sctStatusSctVersion
// col 13 = sctStatusDeviceState
// col 14 = sctTempPowerCycleMin
// col 15 = sctTempPowerCycleMax
// col 16 = sctTempLifetimeMin
// col 17 = sctTempLifetimeMax
// col 18 = sctTempUnderLimitCount
// col 19 = sctTempOverLimitCount
// col 20 = sctSmartStatusPassed
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_health_get_next(void **loop_ctx, void **data_ctx,
                     netsnmp_variable_list *put_idx,
                     netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_health.size()) return nullptr;
    CacheSataHealthRow &row = g_cache.sata_health[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_health_handler(netsnmp_mib_handler *,
                    netsnmp_handler_registration *,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;

    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataHealthRow *row =
            (CacheSataHealthRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;

        switch (tinfo->colnum) {
        case 1:  { long v = row->overall_status;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 2:  { long v = row->offline_status_value;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 3:  { u_long v = row->selftest_status_value;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 4:  set_counter64(req, row->power_cycles); break;
        case 5:  set_counter64(req, row->power_on_hours); break;
        case 6:  { u_long v = row->error_log_count;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 7:  { u_long v = row->pending_defects_count;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 8:  { u_long v = row->selftest_log_count;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 9:  { u_long v = row->selftest_log_err_total;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 10: { u_long v = row->selftest_log_err_outdated;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 11: { u_long v = row->sct_status_format_version;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 12: { u_long v = row->sct_status_sct_version;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 13: { u_long v = row->sct_status_device_state;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 14: { long v = row->sct_temp_power_cycle_min;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 15: { long v = row->sct_temp_power_cycle_max;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 16: { long v = row->sct_temp_lifetime_min;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 17: { long v = row->sct_temp_lifetime_max;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 18: { u_long v = row->sct_temp_under_limit_count;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 19: { u_long v = row->sct_temp_over_limit_count;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 20: { long v = row->sct_smart_status_passed ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA error log table
// INDEX { smartmonDeviceIndex, smartmonSataErrorLogIndex(col 1, NOT-ACCESSIBLE) }
// col 1  = errorIndex (NOT-ACCESSIBLE)
// col 2  = errorNumber
// col 3  = errorLifetimeHours
// col 4  = errorDescription
// col 5  = errorCompRegError
// col 6  = errorCompRegStatus
// col 7  = errorLba
// col 8  = errorRegCommand
// col 9  = errorRegCount
// col 10 = errorRegDevice
// col 11 = errorRegFeature
// col 12 = errorState (SmartmonAtaDeviceState)
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_el_get_next(void **loop_ctx, void **data_ctx,
                 netsnmp_variable_list *put_idx,
                 netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_error_log.size()) return nullptr;
    CacheSataErrorLogRow &row = g_cache.sata_error_log[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.entry_index;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED,
                             (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_el_handler(netsnmp_mib_handler *,
                netsnmp_handler_registration *,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;

    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataErrorLogRow *row =
            (CacheSataErrorLogRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;

        switch (tinfo->colnum) {
        case 2:  { u_long v = row->error_number;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 3:  set_counter64(req, row->lifetime_hours); break;
        case 4:  snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)row->description.c_str(),
                     row->description.size()); break;
        case 5:  { u_long v = row->comp_reg_error;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 6:  { u_long v = row->comp_reg_status;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 7:  set_counter64(req, row->lba); break;
        case 8:  { u_long v = row->reg_command;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 9:  { u_long v = row->reg_count;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 10: { u_long v = row->reg_device;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 11: { u_long v = row->reg_feature;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 12: { long v = (long)(row->state_value & 0x0fu);
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA attribute table
// INDEX { smartmonDeviceIndex, smartmonSataAttrId(col 1, NOT-ACCESSIBLE) }
// col 2  = attrName
// col 3  = attrFlags (BITS)
// col 4  = attrType
// col 5  = attrUpdated
// col 6  = attrValue
// col 7  = attrWorst
// col 8  = attrThreshold
// col 9  = attrRawValue (Counter64)
// col 10 = attrRawString
// col 11 = attrStatus
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_attr_get_next(void **loop_ctx, void **data_ctx,
                   netsnmp_variable_list *put_idx,
                   netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_attrs.size()) return nullptr;
    CacheSataAttrRow &row = g_cache.sata_attrs[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.attr_id;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED,
                             (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_attr_handler(netsnmp_mib_handler *,
                  netsnmp_handler_registration *,
                  netsnmp_agent_request_info *reqinfo,
                  netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;

    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataAttrRow *row =
            (CacheSataAttrRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;

        switch (tinfo->colnum) {
        case 2:  snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)row->name.c_str(), row->name.size()); break;
        case 3:  { uint8_t b = ata_flags_to_bits(row->flags);
                   snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                       &b, 1); break; }
        case 4:  { long v = row->attr_type;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 5:  { long v = row->attr_updated;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 6:  { u_long v = row->value;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 7:  { u_long v = row->worst;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 8:  { u_long v = row->threshold;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 9:  set_counter64(req, (uint64_t)row->raw_value); break;
        case 10: snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)row->raw_string.c_str(),
                     row->raw_string.size()); break;
        case 11: { long v = row->status;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA self-test table
// INDEX { smartmonDeviceIndex, smartmonSataSelfTestIndex(col 1, NOT-ACCESSIBLE) }
// col 2  = selfTestType
// col 3  = selfTestResult
// col 4  = selfTestResultPassed (TruthValue)
// col 5  = selfTestRemainingPct
// col 6  = selfTestLifetimeHours
// col 7  = selfTestLbaFirstError
// col 8  = selfTestEstimatedCompletionTime (DateAndTime, not instantiated when 0)
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_st_get_next(void **loop_ctx, void **data_ctx,
                 netsnmp_variable_list *put_idx,
                 netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_selftests.size()) return nullptr;
    CacheSataSelfTestRow &row = g_cache.sata_selftests[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.entry_index;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED,
                             (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_st_handler(netsnmp_mib_handler *,
                netsnmp_handler_registration *,
                netsnmp_agent_request_info *reqinfo,
                netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;

    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataSelfTestRow *row =
            (CacheSataSelfTestRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;

        switch (tinfo->colnum) {
        case 2:  { long v = row->type;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 3:  { long v = row->result;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 4:  { long v = row->passed ? 1 : 2;  // TruthValue
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 5:  { u_long v = row->remaining_pct;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 6:  set_counter64(req, row->lifetime_hours); break;
        case 7:  set_counter64(req, row->lba_first_error); break;
        case 8:  if (row->estimated_completion == 0) {
                     netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
                 } else {
                     uint8_t dt[8];
                     snmp_encode_date_time(row->estimated_completion, dt);
                     snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                         dt, sizeof(dt));
                 } break;
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA error command table
// INDEX { smartmonDeviceIndex, smartmonSataErrorLogIndex, smartmonSataErrorCmdIndex(col 1) }
// col 1  = errorCmdIndex (NOT-ACCESSIBLE)
// col 2  = regCommand
// col 3  = regCount
// col 4  = regDevice
// col 5  = regError   (from parent error entry completion_registers.error)
// col 6  = regFeature
// col 7  = regLba     (CounterBasedGauge64)
// col 8  = regStatus  (from parent error entry completion_registers.status)
// col 9  = timestamp  (powerup_milliseconds)
// col 10 = description
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_errcmd_get_next(void **loop_ctx, void **data_ctx,
                     netsnmp_variable_list *put_idx,
                     netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_error_cmds.size()) return nullptr;
    CacheSataErrorCmdRow &row = g_cache.sata_error_cmds[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.error_entry_index;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED,
                             (u_char*)&v, sizeof(v));
    v = (u_long)row.cmd_index;
    snmp_set_var_typed_value(put_idx->next_variable->next_variable, ASN_UNSIGNED,
                             (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_errcmd_handler(netsnmp_mib_handler *,
                    netsnmp_handler_registration *,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;

    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataErrorCmdRow *row =
            (CacheSataErrorCmdRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;

        switch (tinfo->colnum) {
        case 2:  { u_long v = row->reg_command;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 3:  { u_long v = row->reg_count;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 4:  { u_long v = row->reg_device;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 5:  { u_long v = row->reg_error;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 6:  { u_long v = row->reg_feature;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 7:  set_counter64(req, row->reg_lba); break;
        case 8:  { u_long v = row->reg_status;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 9:  { u_long v = row->timestamp_ms;
                   snmp_set_var_typed_value(req->requestvb, ASN_GAUGE,
                       (u_char*)&v, sizeof(v)); break; }
        case 10: snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)row->description.c_str(),
                     row->description.size()); break;
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA ERC table
// INDEX { smartmonDeviceIndex, smartmonSataErcIndex(col 1, NOT-ACCESSIBLE) }
// col 2  = enabled (TruthValue)
// col 3  = deciseconds
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_erc_get_next(void **loop_ctx, void **data_ctx,
                  netsnmp_variable_list *put_idx,
                  netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_erc.size()) return nullptr;
    CacheSataErcRow &row = g_cache.sata_erc[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.erc_index;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_erc_handler(netsnmp_mib_handler *,
                 netsnmp_handler_registration *,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataErcRow *row = (CacheSataErcRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;
        switch (tinfo->colnum) {
        case 2:  { long v = row->enabled ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 3:  { u_long v = row->deciseconds;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA PHY event counter table
// INDEX { smartmonDeviceIndex, smartmonSataPhyEventId(col 1, NOT-ACCESSIBLE) }
// col 2  = phyEventName
// col 3  = phyEventSize
// col 4  = phyEventValue (Counter64)
// col 5  = phyEventOverflow (TruthValue)
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_phy_event_get_next(void **loop_ctx, void **data_ctx,
                        netsnmp_variable_list *put_idx,
                        netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_phy_events.size()) return nullptr;
    CacheSataPhyEventRow &row = g_cache.sata_phy_events[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.id;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_phy_event_handler(netsnmp_mib_handler *,
                       netsnmp_handler_registration *,
                       netsnmp_agent_request_info *reqinfo,
                       netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataPhyEventRow *row = (CacheSataPhyEventRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;
        switch (tinfo->colnum) {
        case 2:  snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)row->name.c_str(), row->name.size()); break;
        case 3:  { u_long v = row->size;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 4:  set_counter64(req, row->value); break;
        case 5:  { long v = row->overflow ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA selective self-test table
// INDEX { smartmonDeviceIndex, smartmonSataSelectiveSlot(col 1, NOT-ACCESSIBLE) }
// col 2  = lbaMin (Counter64)
// col 3  = lbaMax (Counter64)
// col 4  = statusValue
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_selective_get_next(void **loop_ctx, void **data_ctx,
                        netsnmp_variable_list *put_idx,
                        netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_selective_tests.size()) return nullptr;
    CacheSataSelectiveTestRow &row = g_cache.sata_selective_tests[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.slot;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_selective_handler(netsnmp_mib_handler *,
                       netsnmp_handler_registration *,
                       netsnmp_agent_request_info *reqinfo,
                       netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataSelectiveTestRow *row = (CacheSataSelectiveTestRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;
        switch (tinfo->colnum) {
        case 2:  set_counter64(req, row->lba_min); break;
        case 3:  set_counter64(req, row->lba_max); break;
        case 4:  { u_long v = row->status_value;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// Scalar handlers for per-device selective self-test log fields (OIDs 28–31)
// These return the value for a given device_index from the health row.
static int sata_selective_revision_handler(netsnmp_mib_handler *,
        netsnmp_handler_registration *, netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    // Return 0 if no single device; for multi-device use case this scalar
    // is device-agnostic (the MIB places it outside the table).
    u_long v = g_cache.sata_health.empty() ? 0 : g_cache.sata_health[0].selective_log_revision;
    snmp_set_var_typed_value(requests->requestvb, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return SNMP_ERR_NOERROR;
}
static int sata_selective_flags_handler(netsnmp_mib_handler *,
        netsnmp_handler_registration *, netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    u_long v = g_cache.sata_health.empty() ? 0 : g_cache.sata_health[0].selective_flags_value;
    snmp_set_var_typed_value(requests->requestvb, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return SNMP_ERR_NOERROR;
}
static int sata_selective_remainder_scan_handler(netsnmp_mib_handler *,
        netsnmp_handler_registration *, netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    long v = (!g_cache.sata_health.empty() && g_cache.sata_health[0].selective_remainder_scan) ? 1 : 2;
    snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (u_char*)&v, sizeof(v));
    return SNMP_ERR_NOERROR;
}
static int sata_selective_powerup_resume_handler(netsnmp_mib_handler *,
        netsnmp_handler_registration *, netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    u_long v = g_cache.sata_health.empty() ? 0 : g_cache.sata_health[0].selective_powerup_resume_min;
    snmp_set_var_typed_value(requests->requestvb, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA log directory table
// INDEX { smartmonDeviceIndex, smartmonSataLogDirAddress(col 1, NOT-ACCESSIBLE) }
// col 2  = logDirName
// col 3  = logDirReadable (TruthValue)
// col 4  = logDirWritable (TruthValue)
// col 5  = logDirGpSectors
// col 6  = logDirSmartSectors
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_logdir_get_next(void **loop_ctx, void **data_ctx,
                     netsnmp_variable_list *put_idx,
                     netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_log_dir.size()) return nullptr;
    CacheSataLogDirRow &row = g_cache.sata_log_dir[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.address;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_logdir_handler(netsnmp_mib_handler *,
                    netsnmp_handler_registration *,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataLogDirRow *row = (CacheSataLogDirRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;
        switch (tinfo->colnum) {
        case 2:  snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)row->name.c_str(), row->name.size()); break;
        case 3:  { long v = row->readable ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 4:  { long v = row->writable ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 5:  { u_long v = row->gp_sectors;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 6:  { u_long v = row->smart_sectors;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// Scalar handlers for log directory per-device scalars (OIDs 35–37)
static int sata_logdir_gp_version_handler(netsnmp_mib_handler *,
        netsnmp_handler_registration *, netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    u_long v = g_cache.sata_health.empty() ? 0 : g_cache.sata_health[0].logdir_gp_version;
    snmp_set_var_typed_value(requests->requestvb, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return SNMP_ERR_NOERROR;
}
static int sata_logdir_smart_version_handler(netsnmp_mib_handler *,
        netsnmp_handler_registration *, netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    u_long v = g_cache.sata_health.empty() ? 0 : g_cache.sata_health[0].logdir_smart_version;
    snmp_set_var_typed_value(requests->requestvb, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return SNMP_ERR_NOERROR;
}
static int sata_logdir_smart_multisector_handler(netsnmp_mib_handler *,
        netsnmp_handler_registration *, netsnmp_agent_request_info *reqinfo,
        netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    long v = (!g_cache.sata_health.empty() && g_cache.sata_health[0].logdir_smart_multisector) ? 1 : 2;
    snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (u_char*)&v, sizeof(v));
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA device statistics table
// INDEX { smartmonDeviceIndex, smartmonSataDevStatPageNum, smartmonSataDevStatOffset }
// col 1  = pageNum (NOT-ACCESSIBLE)
// col 2  = offset  (NOT-ACCESSIBLE)
// col 3  = pageName
// col 4  = name
// col 5  = value (Counter64)
// col 6  = flagsValue
// col 7  = valid (TruthValue)
// col 8  = normalized (TruthValue)
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_devstat_get_next(void **loop_ctx, void **data_ctx,
                      netsnmp_variable_list *put_idx,
                      netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_dev_stats.size()) return nullptr;
    CacheSataDevStatRow &row = g_cache.sata_dev_stats[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.page_num;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.offset;
    snmp_set_var_typed_value(put_idx->next_variable->next_variable, ASN_UNSIGNED,
                             (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_devstat_handler(netsnmp_mib_handler *,
                     netsnmp_handler_registration *,
                     netsnmp_agent_request_info *reqinfo,
                     netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataDevStatRow *row = (CacheSataDevStatRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;
        switch (tinfo->colnum) {
        case 3:  snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)row->page_name.c_str(), row->page_name.size()); break;
        case 4:  snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)row->name.c_str(), row->name.size()); break;
        case 5:  set_counter64(req, row->value); break;
        case 6:  { u_long v = row->flags_value;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 7:  { long v = row->valid ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        case 8:  { long v = row->normalized ? 1 : 2;
                   snmp_set_var_typed_value(req->requestvb, ASN_INTEGER,
                       (u_char*)&v, sizeof(v)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// SATA pending defects LBA table
// INDEX { smartmonDeviceIndex, smartmonSataPendingDefectsIndex(col 1, NOT-ACCESSIBLE) }
// col 1  = pendingDefectsIndex (NOT-ACCESSIBLE)
// col 2  = pendingDefectsLba (CounterBasedGauge64)
// ---------------------------------------------------------------------------

TABLE_ROW_COUNT_HANDLER(sata_pending_def_row_count_handler, sata_pending_defects)
TABLE_LAST_CHANGE_HANDLER(sata_pending_def_last_change_handler, ts_sata_pending_defects)

static netsnmp_variable_list *
sata_pending_def_get_next(void **loop_ctx, void **data_ctx,
                          netsnmp_variable_list *put_idx,
                          netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.sata_pending_defects.size()) return nullptr;
    CacheSataPendingDefectRow &row = g_cache.sata_pending_defects[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = &row;
    u_long v = (u_long)row.device_index;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = (u_long)row.entry_index;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED,
                             (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_pending_def_handler(netsnmp_mib_handler *,
                         netsnmp_handler_registration *,
                         netsnmp_agent_request_info *reqinfo,
                         netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        CacheSataPendingDefectRow *row =
            (CacheSataPendingDefectRow*)netsnmp_extract_iterator_context(req);
        if (!row || !tinfo) continue;
        switch (tinfo->colnum) {
        case 2:  set_counter64(req, row->lba); break;
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// smartSATAChanges subtree — three iterator tables
// Replaces the old smartmonSataInfoTableLastChange scalar at .4.1.2.
// ---------------------------------------------------------------------------

// Table IDs 1-12 map to SATA cache vectors.
struct SataTableMeta { const char *name; size_t row_count; time_t last_change; };
static SataTableMeta sata_table_meta_for(uint32_t tid) {
    switch (tid) {
    case  1: return {"smartmonSataInfoTable",          g_cache.sata_info.size(),            g_cache.ts_sata_info};
    case  2: return {"smartmonSataHealthTable",        g_cache.sata_health.size(),          g_cache.ts_sata_health};
    case  3: return {"smartmonSataAttrTable",          g_cache.sata_attrs.size(),           g_cache.ts_sata_attr};
    case  4: return {"smartmonSataErrorLogTable",      g_cache.sata_error_log.size(),       g_cache.ts_sata_error_log};
    case  5: return {"smartmonSataErrorCmdTable",      g_cache.sata_error_cmds.size(),      g_cache.ts_sata_error_cmd};
    case  6: return {"smartmonSataSelfTestTable",      g_cache.sata_selftests.size(),       g_cache.ts_sata_selftest};
    case  7: return {"smartmonSataErcTable",           g_cache.sata_erc.size(),             g_cache.ts_sata_erc};
    case  8: return {"smartmonSataPhyEventTable",      g_cache.sata_phy_events.size(),      g_cache.ts_sata_phy_event};
    case  9: return {"smartmonSataSelectiveTestTable", g_cache.sata_selective_tests.size(), g_cache.ts_sata_selective_test};
    case 10: return {"smartmonSataLogDirTable",        g_cache.sata_log_dir.size(),         g_cache.ts_sata_log_dir};
    case 11: return {"smartmonSataDevStatTable",       g_cache.sata_dev_stats.size(),       g_cache.ts_sata_dev_stat};
    case 12: return {"smartmonSataPendingDefectsTable",g_cache.sata_pending_defects.size(), g_cache.ts_sata_pending_defects};
    default: return {"", 0, 0};
    }
}

// Count rows belonging to dev_idx in the table identified by tid.
static size_t sata_count_by_device(uint32_t tid, uint32_t dev_idx) {
    size_t n = 0;
    switch (tid) {
    case  1: for (const auto &r : g_cache.sata_info)           if (r.device_index == dev_idx) ++n; break;
    case  2: for (const auto &r : g_cache.sata_health)         if (r.device_index == dev_idx) ++n; break;
    case  3: for (const auto &r : g_cache.sata_attrs)          if (r.device_index == dev_idx) ++n; break;
    case  4: for (const auto &r : g_cache.sata_error_log)      if (r.device_index == dev_idx) ++n; break;
    case  5: for (const auto &r : g_cache.sata_error_cmds)     if (r.device_index == dev_idx) ++n; break;
    case  6: for (const auto &r : g_cache.sata_selftests)      if (r.device_index == dev_idx) ++n; break;
    case  7: for (const auto &r : g_cache.sata_erc)            if (r.device_index == dev_idx) ++n; break;
    case  8: for (const auto &r : g_cache.sata_phy_events)     if (r.device_index == dev_idx) ++n; break;
    case  9: for (const auto &r : g_cache.sata_selective_tests)if (r.device_index == dev_idx) ++n; break;
    case 10: for (const auto &r : g_cache.sata_log_dir)        if (r.device_index == dev_idx) ++n; break;
    case 11: for (const auto &r : g_cache.sata_dev_stats)      if (r.device_index == dev_idx) ++n; break;
    case 12: for (const auto &r : g_cache.sata_pending_defects)if (r.device_index == dev_idx) ++n; break;
    }
    return n;
}

// ---------------------------------------------------------------------------
// smartSATAChangeMetadataTable
// INDEX { smartSATAChangeTableId }  (1 ASN_UNSIGNED index, col 1 NOT-ACCESSIBLE)
// col 2 = smartSATAChangeTableName
// col 3 = smartSATAChangeTableRowCount
// col 4 = smartSATAChangeTableLastChange
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_change_meta_get_next(void **loop_ctx, void **data_ctx,
                          netsnmp_variable_list *put_idx,
                          netsnmp_iterator_info *) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= 12) return nullptr;
    uint32_t tid = (uint32_t)idx + 1;
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = (void*)(uintptr_t)tid;
    u_long v = tid;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_change_meta_handler(netsnmp_mib_handler *,
                         netsnmp_handler_registration *,
                         netsnmp_agent_request_info *reqinfo,
                         netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        uint32_t tid = (uint32_t)(uintptr_t)netsnmp_extract_iterator_context(req);
        if (!tinfo || tid == 0) continue;
        SataTableMeta m = sata_table_meta_for(tid);
        switch (tinfo->colnum) {
        case 2:  snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                     (u_char*)m.name, strlen(m.name)); break;
        case 3:  { u_long v = (u_long)m.row_count;
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 4:  { uint8_t dt[8]; snmp_encode_date_time(m.last_change, dt);
                   snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                       dt, sizeof(dt)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// smartSATAChangeByDeviceTable
// INDEX { smartmonDeviceIndex, smartSATAChangeByDeviceTableId }  (2 ASN_UNSIGNED)
// col 1 = smartSATAChangeByDeviceTableId (NOT-ACCESSIBLE)
// col 2 = smartSATAChangeByDeviceRowCount
// col 3 = smartSATAChangeByDeviceLastChange
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_change_by_dev_get_next(void **loop_ctx, void **data_ctx,
                            netsnmp_variable_list *put_idx,
                            netsnmp_iterator_info *) {
    size_t step = (size_t)(uintptr_t)*loop_ctx;
    size_t dev_vec_idx = step / 12;
    uint32_t table_id  = (uint32_t)(step % 12) + 1;
    if (dev_vec_idx >= g_cache.devices.size()) return nullptr;
    uint32_t dev_idx = g_cache.devices[dev_vec_idx].index;
    *loop_ctx = (void*)(uintptr_t)(step + 1);
    *data_ctx = (void*)(uintptr_t)step;
    u_long v = dev_idx;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = table_id;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_change_by_dev_handler(netsnmp_mib_handler *,
                           netsnmp_handler_registration *,
                           netsnmp_agent_request_info *reqinfo,
                           netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        size_t step = (size_t)(uintptr_t)netsnmp_extract_iterator_context(req);
        if (!tinfo) continue;
        size_t dev_vec_idx = step / 12;
        uint32_t table_id  = (uint32_t)(step % 12) + 1;
        if (dev_vec_idx >= g_cache.devices.size()) continue;
        uint32_t dev_idx = g_cache.devices[dev_vec_idx].index;
        SataTableMeta m = sata_table_meta_for(table_id);
        switch (tinfo->colnum) {
        case 2:  { u_long v = (u_long)sata_count_by_device(table_id, dev_idx);
                   snmp_set_var_typed_value(req->requestvb, ASN_UNSIGNED,
                       (u_char*)&v, sizeof(v)); break; }
        case 3:  { uint64_t key = ((uint64_t)dev_idx << 32) | (uint64_t)table_id;
                   auto it = g_cache.ts_sata_by_dev.find(key);
                   time_t ts = (it != g_cache.ts_sata_by_dev.end()) ? it->second : m.last_change;
                   uint8_t dt[8]; snmp_encode_date_time(ts, dt);
                   snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                       dt, sizeof(dt)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// smartSATAChangeBySubindexTable
// INDEX { smartmonDeviceIndex, smartSATAChangeBySubindexTableId,
//         smartSATAChangeSubindex1, smartSATAChangeSubindex2 }
// Only covers table 5 (sataErrorCmd) and table 11 (sataDevStat).
// col 4 = smartSATAChangeBySubindexLastChange (DateAndTime)
// ---------------------------------------------------------------------------

static netsnmp_variable_list *
sata_change_by_subidx_get_next(void **loop_ctx, void **data_ctx,
                               netsnmp_variable_list *put_idx,
                               netsnmp_iterator_info *) {
    size_t idx         = (size_t)(uintptr_t)*loop_ctx;
    size_t errcmd_size = g_cache.sata_error_cmds.size();
    size_t devstat_size= g_cache.sata_dev_stats.size();
    if (idx >= errcmd_size + devstat_size) return nullptr;

    uint32_t dev_idx, table_id, sub1, sub2;
    if (idx < errcmd_size) {
        const CacheSataErrorCmdRow &r = g_cache.sata_error_cmds[idx];
        dev_idx  = r.device_index;
        table_id = 5;
        sub1     = r.error_entry_index;
        sub2     = r.cmd_index;
    } else {
        const CacheSataDevStatRow &r = g_cache.sata_dev_stats[idx - errcmd_size];
        dev_idx  = r.device_index;
        table_id = 11;
        sub1     = r.page_num;
        sub2     = r.offset;
    }
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    *data_ctx = (void*)(uintptr_t)idx;

    u_long v = dev_idx;
    snmp_set_var_typed_value(put_idx, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = table_id;
    snmp_set_var_typed_value(put_idx->next_variable, ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = sub1;
    snmp_set_var_typed_value(put_idx->next_variable->next_variable,
                             ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    v = sub2;
    snmp_set_var_typed_value(put_idx->next_variable->next_variable->next_variable,
                             ASN_UNSIGNED, (u_char*)&v, sizeof(v));
    return put_idx;
}

static int
sata_change_by_subidx_handler(netsnmp_mib_handler *,
                               netsnmp_handler_registration *,
                               netsnmp_agent_request_info *reqinfo,
                               netsnmp_request_info *requests) {
    if (reqinfo->mode != MODE_GET) return SNMP_ERR_NOERROR;
    for (netsnmp_request_info *req = requests; req; req = req->next) {
        netsnmp_table_request_info *tinfo = netsnmp_extract_table_info(req);
        size_t idx = (size_t)(uintptr_t)netsnmp_extract_iterator_context(req);
        if (!tinfo) continue;
        size_t errcmd_size = g_cache.sata_error_cmds.size();
        time_t ts;
        if (idx < errcmd_size) {
            uint32_t dev = g_cache.sata_error_cmds[idx].device_index;
            uint64_t key = ((uint64_t)dev << 32) | 5;
            auto it = g_cache.ts_sata_by_dev.find(key);
            ts = (it != g_cache.ts_sata_by_dev.end()) ? it->second : g_cache.ts_sata_error_cmd;
        } else {
            const CacheSataDevStatRow &dr = g_cache.sata_dev_stats[idx - errcmd_size];
            uint64_t key = sata_devstat_row_key(dr.device_index, dr.page_num, dr.offset);
            auto it = g_cache.ts_sata_devstat_by_row.find(key);
            ts = (it != g_cache.ts_sata_devstat_by_row.end()) ? it->second : g_cache.ts_sata_dev_stat;
        }
        switch (tinfo->colnum) {
        case 4:  { uint8_t dt[8]; snmp_encode_date_time(ts, dt);
                   snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                       dt, sizeof(dt)); break; }
        default: netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void register_sata_mib() {
    // Row-count and last-change scalars for each implemented table
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataInfoTableRowCount",        sata_info_row_count_handler,
        oid_sata_info_row_count,        OID_LEN(oid_sata_info_row_count),        HANDLER_CAN_RONLY));

    // smartSATAChanges subtree (.4.1.2) — three change-tracking tables
    REG_TABLE_U("smartSATAChangeMetadataTable",
                sata_change_meta_handler, oid_sata_change_metadata_table,
                sata_change_meta_get_next, 2, 4);
    REG_TABLE_UU("smartSATAChangeByDeviceTable",
                 sata_change_by_dev_handler, oid_sata_change_by_device_table,
                 sata_change_by_dev_get_next, 2, 3);
    {
        static const int _idx4[] = { ASN_UNSIGNED, ASN_UNSIGNED,
                                     ASN_UNSIGNED, ASN_UNSIGNED, 0 };
        register_table_ronly("smartSATAChangeBySubindexTable",
                             sata_change_by_subidx_handler,
                             oid_sata_change_by_subindex_table,
                             OID_LEN(oid_sata_change_by_subindex_table),
                             snmp_table_get_first,
                             sata_change_by_subidx_get_next,
                             4, 4, _idx4);
    }

    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataHealthTableRowCount",      sata_health_row_count_handler,
        oid_sata_health_row_count,      OID_LEN(oid_sata_health_row_count),      HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataHealthTableLastChange",    sata_health_last_change_handler,
        oid_sata_health_last_change,    OID_LEN(oid_sata_health_last_change),    HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataAttrTableRowCount",        sata_attr_row_count_handler,
        oid_sata_attr_row_count,        OID_LEN(oid_sata_attr_row_count),        HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataAttrTableLastChange",      sata_attr_last_change_handler,
        oid_sata_attr_last_change,      OID_LEN(oid_sata_attr_last_change),      HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataErrorLogTableRowCount",    sata_el_row_count_handler,
        oid_sata_error_log_row_count,   OID_LEN(oid_sata_error_log_row_count),   HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataErrorLogTableLastChange",  sata_el_last_change_handler,
        oid_sata_error_log_last_change, OID_LEN(oid_sata_error_log_last_change), HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataSelfTestTableRowCount",    sata_st_row_count_handler,
        oid_sata_selftest_row_count,    OID_LEN(oid_sata_selftest_row_count),    HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataSelfTestTableLastChange",  sata_st_last_change_handler,
        oid_sata_selftest_last_change,  OID_LEN(oid_sata_selftest_last_change),  HANDLER_CAN_RONLY));

    // SATA table iterator registrations
    REG_TABLE_U("smartmonSataInfoTable",      sata_info_handler,   oid_sata_info_table,      sata_info_get_next,    1, 49);
    REG_TABLE_U("smartmonSataHealthTable",    sata_health_handler, oid_sata_health_table,    sata_health_get_next,  1, 20);
    REG_TABLE_UU("smartmonSataErrorLogTable", sata_el_handler,     oid_sata_error_log_table, sata_el_get_next,      2, 12);
    REG_TABLE_UU("smartmonSataAttrTable",     sata_attr_handler,   oid_sata_attr_table,      sata_attr_get_next,    2, 11);

    // SATA error cmd table metadata scalars
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataErrorCmdTableRowCount",    sata_errcmd_row_count_handler,
        oid_sata_error_cmd_row_count,   OID_LEN(oid_sata_error_cmd_row_count),   HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataErrorCmdTableLastChange",  sata_errcmd_last_change_handler,
        oid_sata_error_cmd_last_change, OID_LEN(oid_sata_error_cmd_last_change), HANDLER_CAN_RONLY));

    // SATA error cmd table (3 index columns: deviceIndex + errorLogIndex + cmdIndex)
    REG_TABLE_UUU("smartmonSataErrorCmdTable", sata_errcmd_handler, oid_sata_error_cmd_table, sata_errcmd_get_next, 2, 10);

    REG_TABLE_UU("smartmonSataSelfTestTable",  sata_st_handler,    oid_sata_selftest_table,  sata_st_get_next,      2, 8);

    // ERC table
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataErcTableRowCount",         sata_erc_row_count_handler,
        oid_sata_erc_row_count,         OID_LEN(oid_sata_erc_row_count),         HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataErcTableLastChange",       sata_erc_last_change_handler,
        oid_sata_erc_last_change,       OID_LEN(oid_sata_erc_last_change),       HANDLER_CAN_RONLY));
    REG_TABLE_UU("smartmonSataErcTable", sata_erc_handler, oid_sata_erc_table, sata_erc_get_next, 2, 3);

    // PHY event counter table
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataPhyEventTableRowCount",    sata_phy_event_row_count_handler,
        oid_sata_phy_event_row_count,   OID_LEN(oid_sata_phy_event_row_count),   HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataPhyEventTableLastChange",  sata_phy_event_last_change_handler,
        oid_sata_phy_event_last_change, OID_LEN(oid_sata_phy_event_last_change), HANDLER_CAN_RONLY));
    REG_TABLE_UU("smartmonSataPhyEventTable", sata_phy_event_handler, oid_sata_phy_event_table, sata_phy_event_get_next, 2, 5);

    // Selective self-test table + per-device scalars
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataSelectiveTableRowCount",   sata_selective_row_count_handler,
        oid_sata_selective_row_count,   OID_LEN(oid_sata_selective_row_count),   HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataSelectiveTableLastChange", sata_selective_last_change_handler,
        oid_sata_selective_last_change, OID_LEN(oid_sata_selective_last_change), HANDLER_CAN_RONLY));
    REG_TABLE_UU("smartmonSataSelectiveTable", sata_selective_handler, oid_sata_selective_table, sata_selective_get_next, 2, 4);
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataSelectiveRevision",        sata_selective_revision_handler,
        oid_sata_selective_revision,    OID_LEN(oid_sata_selective_revision),    HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataSelectiveFlags",           sata_selective_flags_handler,
        oid_sata_selective_flags,       OID_LEN(oid_sata_selective_flags),       HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataSelectiveRemainderScan",   sata_selective_remainder_scan_handler,
        oid_sata_selective_remainder_scan, OID_LEN(oid_sata_selective_remainder_scan), HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataSelectivePowerupResume",   sata_selective_powerup_resume_handler,
        oid_sata_selective_powerup_resume, OID_LEN(oid_sata_selective_powerup_resume), HANDLER_CAN_RONLY));

    // Log directory table + per-device scalars
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataLogDirTableRowCount",      sata_logdir_row_count_handler,
        oid_sata_logdir_row_count,      OID_LEN(oid_sata_logdir_row_count),      HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataLogDirTableLastChange",    sata_logdir_last_change_handler,
        oid_sata_logdir_last_change,    OID_LEN(oid_sata_logdir_last_change),    HANDLER_CAN_RONLY));
    REG_TABLE_UU("smartmonSataLogDirTable", sata_logdir_handler, oid_sata_logdir_table, sata_logdir_get_next, 2, 6);
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataLogDirGpVersion",          sata_logdir_gp_version_handler,
        oid_sata_logdir_gp_version,     OID_LEN(oid_sata_logdir_gp_version),     HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataLogDirSmartVersion",       sata_logdir_smart_version_handler,
        oid_sata_logdir_smart_version,  OID_LEN(oid_sata_logdir_smart_version),  HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataLogDirSmartMultisector",   sata_logdir_smart_multisector_handler,
        oid_sata_logdir_smart_multisector, OID_LEN(oid_sata_logdir_smart_multisector), HANDLER_CAN_RONLY));

    // Device statistics table
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataDevStatTableRowCount",     sata_devstat_row_count_handler,
        oid_sata_devstat_row_count,     OID_LEN(oid_sata_devstat_row_count),     HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataDevStatTableLastChange",   sata_devstat_last_change_handler,
        oid_sata_devstat_last_change,   OID_LEN(oid_sata_devstat_last_change),   HANDLER_CAN_RONLY));
    REG_TABLE_UUU("smartmonSataDevStatTable", sata_devstat_handler, oid_sata_devstat_table, sata_devstat_get_next, 3, 8);

    // Pending defects LBA table
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataPendingDefTableRowCount",  sata_pending_def_row_count_handler,
        oid_sata_pending_def_row_count, OID_LEN(oid_sata_pending_def_row_count), HANDLER_CAN_RONLY));
    netsnmp_register_scalar(netsnmp_create_handler_registration(
        "sataPendingDefTableLastChange",sata_pending_def_last_change_handler,
        oid_sata_pending_def_last_change, OID_LEN(oid_sata_pending_def_last_change), HANDLER_CAN_RONLY));
    REG_TABLE_UU("smartmonSataPendingDefectsTable", sata_pending_def_handler,
                 oid_sata_pending_def_table, sata_pending_def_get_next, 2, 2);
}
