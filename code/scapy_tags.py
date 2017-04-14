# Author: Pieter Robyns, 2017
# License: GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
# See LICENSE in this Git repository for the full license description

TAG_SSID                      = 0
TAG_SUPP_RATES                = 1
TAG_FH_PARAMETER              = 2
TAG_DS_PARAMETER              = 3
TAG_CF_PARAMETER              = 4
TAG_TIM                       = 5
TAG_IBSS_PARAMETER            = 6
TAG_COUNTRY_INFO              = 7
TAG_FH_HOPPING_PARAMETER      = 8
TAG_FH_HOPPING_TABLE          = 9
TAG_REQUEST                  = 10
TAG_QBSS_LOAD                = 11
TAG_EDCA_PARAM_SET           = 12
TAG_TSPEC                    = 13
TAG_TCLAS                    = 14
TAG_SCHEDULE                 = 15
TAG_CHALLENGE_TEXT           = 16

TAG_POWER_CONSTRAINT         = 32
TAG_POWER_CAPABILITY         = 33
TAG_TPC_REQUEST              = 34
TAG_TPC_REPORT               = 35
TAG_SUPPORTED_CHANNELS       = 36
TAG_CHANNEL_SWITCH_ANN       = 37
TAG_MEASURE_REQ              = 38
TAG_MEASURE_REP              = 39
TAG_QUIET                    = 40
TAG_IBSS_DFS                 = 41
TAG_ERP_INFO                 = 42
TAG_TS_DELAY                 = 43
TAG_TCLAS_PROCESS            = 44
TAG_HT_CAPABILITY            = 45 # /* IEEE Stc 802.11n/D2.0 */
TAG_QOS_CAPABILITY           = 46
TAG_ERP_INFO_OLD             = 47 # /* IEEE Std 802.11g/D4.0 */
TAG_RSN_IE                   = 48
## /* Reserved 49 */
TAG_EXT_SUPP_RATES           = 50
TAG_AP_CHANNEL_REPORT        = 51
TAG_NEIGHBOR_REPORT          = 52
TAG_RCPI                     = 53
TAG_MOBILITY_DOMAIN          = 54  # /* IEEE Std 802.11r-2008 */
TAG_FAST_BSS_TRANSITION      = 55  # /* IEEE Std 802.11r-2008 */
TAG_TIMEOUT_INTERVAL         = 56  # /* IEEE Std 802.11r-2008 */
TAG_RIC_DATA                 = 57  # /* IEEE Std 802.11r-2008 */
TAG_DSE_REG_LOCATION         = 58
TAG_SUPPORTED_REGULATORY_CLASSES           = 59 # /* IEEE Std 802.11w-2009 */
TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT   = 60 # /* IEEE Std 802.11w-2009 */
TAG_HT_INFO                  = 61  # /* IEEE Stc 802.11n/D2.0 */
TAG_SECONDARY_CHANNEL_OFFSET = 62  # /* IEEE Stc 802.11n/D1.10/D2.0 */
TAG_BSS_AVG_ACCESS_DELAY     = 63
TAG_ANTENNA                  = 64
TAG_RSNI                     = 65
TAG_MEASURE_PILOT_TRANS      = 66
TAG_BSS_AVB_ADM_CAPACITY     = 67
TAG_IE_68_CONFLICT           = 68  # /* Conflict: WAPI Vs. IEEE */
TAG_WAPI_PARAM_SET           = 68
TAG_BSS_AC_ACCESS_DELAY      = 68
TAG_TIME_ADV                 = 69  # /* IEEE Std 802.11p-2010 */
TAG_RM_ENABLED_CAPABILITY    = 70
TAG_MULTIPLE_BSSID           = 71
TAG_20_40_BSS_CO_EX          = 72  # /* IEEE P802.11n/D6.0 */
TAG_20_40_BSS_INTOL_CH_REP   = 73  # /* IEEE P802.11n/D6.0 */
TAG_OVERLAP_BSS_SCAN_PAR     = 74  # /* IEEE P802.11n/D6.0 */
TAG_RIC_DESCRIPTOR           = 75  # /* IEEE Std 802.11r-2008 */
TAG_MMIE                     = 76  # /* IEEE Std 802.11w-2009 */
TAG_EVENT_REQUEST            = 78
TAG_EVENT_REPORT             = 79
TAG_DIAGNOSTIC_REQUEST       = 80
TAG_DIAGNOSTIC_REPORT        = 81
TAG_LOCATION_PARAMETERS      = 82
TAG_NO_BSSID_CAPABILITY      = 83
TAG_SSID_LIST                = 84
TAG_MULTIPLE_BSSID_INDEX     = 85
TAG_FMS_DESCRIPTOR           = 86
TAG_FMS_REQUEST              = 87
TAG_FMS_RESPONSE             = 88
TAG_QOS_TRAFFIC_CAPABILITY   = 89
TAG_BSS_MAX_IDLE_PERIOD      = 90
TAG_TFS_REQUEST              = 91
TAG_TFS_RESPONSE             = 92
TAG_WNM_SLEEP_MODE           = 93
TAG_TIM_BROADCAST_REQUEST    = 94
TAG_TIM_BROADCAST_RESPONSE   = 95
TAG_COLLOCATED_INTER_REPORT  = 96
TAG_CHANNEL_USAGE            = 97
TAG_TIME_ZONE                = 98  # /* IEEE Std 802.11v-2011 */
TAG_DMS_REQUEST              = 99
TAG_DMS_RESPONSE            = 100
TAG_LINK_IDENTIFIER         = 101  # /* IEEE Std 802.11z-2010 */
TAG_WAKEUP_SCHEDULE         = 102  # /* IEEE Std 802.11z-2010 */
TAG_CHANNEL_SWITCH_TIMING   = 104  # /* IEEE Std 802.11z-2010 */
TAG_PTI_CONTROL             = 105  # /* IEEE Std 802.11z-2010 */
TAG_PU_BUFFER_STATUS        = 106  # /* IEEE Std 802.11z-2010 */
TAG_INTERWORKING            = 107  # /* IEEE Std 802.11u-2011 */
TAG_ADVERTISEMENT_PROTOCOL  = 108  # /* IEEE Std 802.11u-2011 */
TAG_EXPIDITED_BANDWIDTH_REQ = 109  # /* IEEE Std 802.11u-2011 */
TAG_QOS_MAP_SET             = 110  # /* IEEE Std 802.11u-2011 */
TAG_ROAMING_CONSORTIUM      = 111  # /* IEEE Std 802.11u-2011 */
TAG_EMERGENCY_ALERT_ID      = 112  # /* IEEE Std 802.11u-2011 */
TAG_MESH_CONFIGURATION      = 113  # /* IEEE Std 802.11s-2011 */
TAG_MESH_ID                 = 114  # /* IEEE Std 802.11s-2011 */
TAG_MESH_LINK_METRIC_REPORT = 115
TAG_CONGESTION_NOTIFICATION = 116
TAG_MESH_PEERING_MGMT       = 117  # /* IEEE Std 802.11s-2011 */
TAG_MESH_CHANNEL_SWITCH     = 118
TAG_MESH_AWAKE_WINDOW       = 119
TAG_BEACON_TIMING           = 120
TAG_MCCAOP_SETUP_REQUEST    = 121
TAG_MCCAOP_SETUP_REPLY      = 122
TAG_MCCAOP_ADVERTISSEMENT   = 123
TAG_MCCAOP_TEARDOWN         = 124
TAG_GANN                    = 125
TAG_RANN                    = 126  # /* IEEE Std 802.11s-2011 */
TAG_EXTENDED_CAPABILITIES   = 127  # /* IEEE Stc 802.11n/D1.10/D2.0 */
TAG_AGERE_PROPRIETARY       = 128
TAG_MESH_PREQ               = 130  # /* IEEE Std 802.11s-2011 */
TAG_MESH_PREP               = 131  # /* IEEE Std 802.11s-2011 */
TAG_MESH_PERR               = 132  # /* IEEE Std 802.11s-2011 */
TAG_CISCO_CCX1_CKIP         = 133  # /* Cisco Compatible eXtensions v1 */
TAG_CISCO_CCX2              = 136  # /* Cisco Compatible eXtensions v2 */
TAG_PXU                     = 137
TAG_PXUC                    = 138
TAG_AUTH_MESH_PEERING_EXCH  = 139
TAG_MIC                     = 140
TAG_DESTINATION_URI         = 141
TAG_U_APSD_COEX             = 142
TAG_CISCO_CCX3              = 149  # /* Cisco Compatible eXtensions v3 */
TAG_CISCO_UNKNOWN_96        = 150  # /* Cisco Compatible eXtensions */
TAG_SYMBOL_PROPRIETARY      = 173
TAG_MCCAOP_ADVERTISSEMENT_OV= 174
TAG_VHT_CAPABILITY          = 191  # /* IEEE Std 802.11ac/D3.1 */
TAG_VHT_OPERATION           = 192  # /* IEEE Std 802.11ac/D3.1 */
TAG_VHT_TX_PWR_ENVELOPE     = 195  # /* IEEE Std 802.11ac/D5.0 */
TAG_VENDOR_SPECIFIC_IE      = 221

elt_id_map = {
   TAG_SSID:                                 "SSID parameter set" ,
   TAG_SUPP_RATES:                           "Supported Rates" ,
   TAG_FH_PARAMETER:                         "FH Parameter set" ,
   TAG_DS_PARAMETER:                         "DS Parameter set" ,
   TAG_CF_PARAMETER:                         "CF Parameter set" ,
   TAG_TIM:                                  "Traffic Indication Map (TIM)" ,
   TAG_IBSS_PARAMETER:                       "IBSS Parameter set" ,
   TAG_COUNTRY_INFO:                         "Country Information" ,
   TAG_FH_HOPPING_PARAMETER:                 "Hopping Pattern Parameters" ,
   TAG_FH_HOPPING_TABLE:                     "Hopping Pattern Table" ,
   TAG_REQUEST:                              "Request" ,
   TAG_QBSS_LOAD:                            "QBSS Load Element" ,
   TAG_EDCA_PARAM_SET:                       "EDCA Parameter Set" ,
   TAG_TSPEC:                                "Traffic Specification" ,
   TAG_TCLAS:                                "Traffic Classification" ,
   TAG_SCHEDULE:                             "Schedule" ,
   TAG_CHALLENGE_TEXT:                       "Challenge text" ,
   TAG_POWER_CONSTRAINT:                     "Power Constraint" ,
   TAG_POWER_CAPABILITY:                     "Power Capability" ,
   TAG_TPC_REQUEST:                          "TPC Request" ,
   TAG_TPC_REPORT:                           "TPC Report" ,
   TAG_SUPPORTED_CHANNELS:                   "Supported Channels" ,
   TAG_CHANNEL_SWITCH_ANN:                   "Channel Switch Announcement" ,
   TAG_MEASURE_REQ:                          "Measurement Request" ,
   TAG_MEASURE_REP:                          "Measurement Report" ,
   TAG_QUIET:                                "Quiet" ,
   TAG_IBSS_DFS:                             "IBSS DFS" ,
   TAG_ERP_INFO:                             "ERP Information" ,
   TAG_TS_DELAY:                             "TS Delay" ,
   TAG_TCLAS_PROCESS:                        "TCLAS Processing" ,
   TAG_HT_CAPABILITY:                        "HT Capabilities" ,
   TAG_QOS_CAPABILITY:                       "QoS Capability" ,
   TAG_ERP_INFO_OLD:                         "ERP Information" , # /* Reserved... */
   TAG_RSN_IE:                               "RSN Information" ,
   TAG_EXT_SUPP_RATES:                       "Extended Supported Rates" ,
   TAG_AP_CHANNEL_REPORT:                    "AP Channel Report" ,
   TAG_NEIGHBOR_REPORT:                      "Neighbor Report" ,
   TAG_RCPI:                                 "RCPI" ,
   TAG_MOBILITY_DOMAIN:                      "Mobility Domain" ,
   TAG_FAST_BSS_TRANSITION:                  "Fast BSS Transition" ,
   TAG_TIMEOUT_INTERVAL:                     "Timeout Interval" ,
   TAG_RIC_DATA:                             "RIC Data" ,
   TAG_DSE_REG_LOCATION:                     "DSE Registered Location" ,
   TAG_SUPPORTED_REGULATORY_CLASSES:         "Supported Regulatory Classes" ,
   TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT: "Extended Channel Switch Announcement" ,
   TAG_HT_INFO:                              "HT Information" ,
   TAG_SECONDARY_CHANNEL_OFFSET:             "Secondary Channel Offset" ,
   TAG_BSS_AVG_ACCESS_DELAY:                 "BSS Average Access Delay" ,
   TAG_ANTENNA:                              "Antenna" ,
   TAG_RSNI:                                 "RSNI" ,
   TAG_MEASURE_PILOT_TRANS:                  "Measurement Pilot Transmission" ,
   TAG_BSS_AVB_ADM_CAPACITY:                 "BSS Available Admission Capacity" ,
   TAG_IE_68_CONFLICT:                       "BSS AC Access Delay/WAPI Parameter Set" ,
   TAG_TIME_ADV:                             "Time Advertisement" ,
   TAG_RM_ENABLED_CAPABILITY:                "RM Enabled Capabilities" ,
   TAG_MULTIPLE_BSSID:                       "Multiple BSSID" ,
   TAG_20_40_BSS_CO_EX:                      "20/40 BSS Coexistence" ,
   TAG_20_40_BSS_INTOL_CH_REP:               "20/40 BSS Intolerant Channel Report" ,   # /* IEEE P802.11n/D6.0 */
   TAG_OVERLAP_BSS_SCAN_PAR:                 "Overlapping BSS Scan Parameters" ,       # /* IEEE P802.11n/D6.0 */
   TAG_RIC_DESCRIPTOR:                       "RIC Descriptor" ,
   TAG_MMIE:                                 "Management MIC" ,
   TAG_EVENT_REQUEST:                        "Event Request" ,
   TAG_EVENT_REPORT:                         "Event Report" ,
   TAG_DIAGNOSTIC_REQUEST:                   "Diagnostic Request" ,
   TAG_DIAGNOSTIC_REPORT:                    "Diagnostic Report" ,
   TAG_LOCATION_PARAMETERS:                  "Location Parameters" ,
   TAG_NO_BSSID_CAPABILITY:                  "Non Transmitted BSSID Capability" ,
   TAG_SSID_LIST:                            "SSID List" ,
   TAG_MULTIPLE_BSSID_INDEX:                 "Multiple BSSID Index" ,
   TAG_FMS_DESCRIPTOR:                       "FMS Descriptor" ,
   TAG_FMS_REQUEST:                          "FMS Request" ,
   TAG_FMS_RESPONSE:                         "FMS Response" ,
   TAG_QOS_TRAFFIC_CAPABILITY:               "QoS Traffic Capability" ,
   TAG_BSS_MAX_IDLE_PERIOD:                  "BSS Max Idle Period" ,
   TAG_TFS_REQUEST:                          "TFS Request" ,
   TAG_TFS_RESPONSE:                         "TFS Response" ,
   TAG_WNM_SLEEP_MODE:                       "WNM-Sleep Mode" ,
   TAG_TIM_BROADCAST_REQUEST:                "TIM Broadcast Request" ,
   TAG_TIM_BROADCAST_RESPONSE:               "TIM Broadcast Response" ,
   TAG_COLLOCATED_INTER_REPORT:              "Collocated Interference Report" ,
   TAG_CHANNEL_USAGE:                        "Channel Usage" ,
   TAG_TIME_ZONE:                            "Time Zone" ,
   TAG_DMS_REQUEST:                          "DMS Request" ,
   TAG_DMS_RESPONSE:                         "DMS Response" ,
   TAG_LINK_IDENTIFIER:                      "Link Identifier" ,
   TAG_WAKEUP_SCHEDULE:                      "Wakeup Schedule" ,
   TAG_CHANNEL_SWITCH_TIMING:                "Channel Switch Timing" ,
   TAG_PTI_CONTROL:                          "PTI Control" ,
   TAG_PU_BUFFER_STATUS:                     "PU Buffer Status" ,
   TAG_INTERWORKING:                         "Interworking" ,
   TAG_ADVERTISEMENT_PROTOCOL:               "Advertisement Protocol",
   TAG_EXPIDITED_BANDWIDTH_REQ:              "Expedited Bandwidth Request" ,
   TAG_QOS_MAP_SET:                          "QoS Map Set" ,
   TAG_ROAMING_CONSORTIUM:                   "Roaming Consortium" ,
   TAG_EMERGENCY_ALERT_ID:                   "Emergency Alert Identifier" ,
   TAG_MESH_CONFIGURATION:                   "Mesh Configuration" ,
   TAG_MESH_ID:                              "Mesh ID" ,
   TAG_MESH_LINK_METRIC_REPORT:              "Mesh Link Metric Report" ,
   TAG_CONGESTION_NOTIFICATION:              "Congestion Notification" ,
   TAG_MESH_PEERING_MGMT:                    "Mesh Peering Management" ,
   TAG_MESH_CHANNEL_SWITCH:                  "Mesh Channel Switch Parameters" ,
   TAG_MESH_AWAKE_WINDOW:                    "Mesh Awake Windows" ,
   TAG_BEACON_TIMING:                        "Beacon Timing" ,
   TAG_MCCAOP_SETUP_REQUEST:                 "MCCAOP Setup Request" ,
   TAG_MCCAOP_SETUP_REPLY:                   "MCCAOP SETUP Reply" ,
   TAG_MCCAOP_ADVERTISSEMENT:                "MCCAOP Advertissement" ,
   TAG_MCCAOP_TEARDOWN:                      "MCCAOP Teardown" ,
   TAG_GANN:                                 "Gate Announcemen" ,
   TAG_RANN:                                 "Root Announcement" ,
   TAG_EXTENDED_CAPABILITIES:                "Extended Capabilities" ,
   TAG_AGERE_PROPRIETARY:                    "Agere Proprietary" ,
   TAG_MESH_PREQ:                            "Path Request" ,
   TAG_MESH_PREP:                            "Path Reply" ,
   TAG_MESH_PERR:                            "Path Error" ,
   TAG_CISCO_CCX1_CKIP:                      "Cisco CCX1 CKIP + Device Name" ,
   TAG_CISCO_CCX2:                           "Cisco CCX2" ,
   TAG_PXU:                                  "Proxy Update" ,
   TAG_PXUC:                                 "Proxy Update Confirmation",
   TAG_AUTH_MESH_PEERING_EXCH:               "Authenticated Mesh Peering Exchange" ,
   TAG_MIC:                                  "MIC (Message Integrity Code)" ,
   TAG_DESTINATION_URI:                      "Destination URI" ,
   TAG_U_APSD_COEX:                          "U-APSD Coexistence" ,
   TAG_CISCO_CCX3:                           "Cisco Unknown 95" ,
   TAG_CISCO_UNKNOWN_96:                     "Cisco Unknown 96" ,
   TAG_SYMBOL_PROPRIETARY:                   "Symbol Proprietary" ,
   TAG_MCCAOP_ADVERTISSEMENT_OV:             "MCCAOP Advertisement Overview" ,
   TAG_VHT_CAPABILITY:                       "VHT Capabilities" ,
   TAG_VHT_OPERATION:                        "VHT Operation" ,
   TAG_VHT_TX_PWR_ENVELOPE:                  "VHT Tx Power Envelope" ,
   TAG_VENDOR_SPECIFIC_IE:                   "Vendor Specific" ,
}

def human_readable_elt(elt_id):
    # Human readable elt_id?
    name = "Nonexistent"
    try:
        name = elt_id_map[elt_id]
    except KeyError as e:
        pass

    return name
