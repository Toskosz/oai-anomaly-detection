/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 * contact@openairinterface.org
 */

#include "../../../../src/xApp/e42_xapp_api.h"
#include "../../../../src/sm/rc_sm/ie/ir/ran_param_struct.h"
#include "../../../../src/sm/rc_sm/ie/ir/ran_param_list.h"
#include "../../../../src/util/time_now_us.h"
#include "../../../../src/util/alg_ds/ds/lock_guard/lock_guard.h"
#include "../../../../src/sm/rc_sm/rc_sm_id.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sqlite3.h> // Added for SQLite functionality
#include <stdbool.h> // Added for bool type

#define PORT 8080
#define MAX_CLIENTS 2 // Represents the number of slices we are managing
#define BUFFER_SIZE 2000
#define SERVER_IP "192.168.70.1" // Replace with your server's IP address
#define DB_PATH "messages.db" // Path to the SQLite database
#define POLLING_INTERVAL_US 1000000 // Poll database every 1 second

// Holds the state for each slice being managed
typedef struct {
    int sst;
    int sd;
    int prb_allocation;      // Current PRB allocation (0 or 100)
    int prev_prb_allocation; // Previous PRB allocation
    int rrc_ue_id;           // Mapped RRC UE ID for release
} ue_data_t;


ue_data_t ue_data[MAX_CLIENTS];
sqlite3 *db; // SQLite database handle
sqlite3_stmt *select_stmt; // Prepared SELECT statement
sqlite3_stmt *update_stmt; // Prepared UPDATE statement

typedef enum{
    DRX_parameter_configuration_7_6_3_1 = 1,
    SR_periodicity_configuration_7_6_3_1 = 2,
    SPS_parameters_configuration_7_6_3_1 = 3,
    Configured_grant_control_7_6_3_1 = 4,
    CQI_table_configuration_7_6_3_1 = 5,
    Slice_level_PRB_quotal_7_6_3_1 = 6,
} rc_ctrl_service_style_2_act_id_e;

static
e2sm_rc_ctrl_hdr_frmt_1_t gen_rc_ctrl_hdr_frmt_1(ue_id_e2sm_t ue_id, uint32_t ric_style_type, uint16_t ctrl_act_id)
{
  e2sm_rc_ctrl_hdr_frmt_1_t dst = {0};

  // 6.2.2.6
  dst.ue_id = cp_ue_id_e2sm(&ue_id);

  dst.ric_style_type = ric_style_type;
  dst.ctrl_act_id = ctrl_act_id;

  return dst;
}

static
e2sm_rc_ctrl_hdr_t gen_rc_ctrl_hdr(e2sm_rc_ctrl_hdr_e hdr_frmt, ue_id_e2sm_t ue_id, uint32_t ric_style_type, uint16_t ctrl_act_id)
{
  e2sm_rc_ctrl_hdr_t dst = {0};

  if (hdr_frmt == FORMAT_1_E2SM_RC_CTRL_HDR) {
    dst.format = FORMAT_1_E2SM_RC_CTRL_HDR;
    dst.frmt_1 = gen_rc_ctrl_hdr_frmt_1(ue_id, ric_style_type, ctrl_act_id);
  } else {
    assert(0!=0 && "not implemented the fill func for this ctrl hdr frmt");
  }

  return dst;
}

typedef enum {
    RRM_Policy_Ratio_List_8_4_3_6 = 1,
    RRM_Policy_Ratio_Group_8_4_3_6 = 2,
    RRM_Policy_8_4_3_6 = 3,
    RRM_Policy_Member_List_8_4_3_6 = 4,
    RRM_Policy_Member_8_4_3_6 = 5,
    PLMN_Identity_8_4_3_6 = 6,
    S_NSSAI_8_4_3_6 = 7,
    SST_8_4_3_6 = 8,
    SD_8_4_3_6 = 9,
    Min_PRB_Policy_Ratio_8_4_3_6 = 10,
    Max_PRB_Policy_Ratio_8_4_3_6 = 11,
    Dedicated_PRB_Policy_Ratio_8_4_3_6 = 12,
} slice_level_PRB_quota_param_id_e;

static
void gen_rrm_policy_ratio_group(lst_ran_param_t* RRM_Policy_Ratio_Group,
                                const char* sst_str,
                                const char* sd_str,
                                int min_ratio_prb,
                                int dedicated_ratio_prb,
                                int max_ratio_prb)
{
  // RRM Policy Ratio Group, STRUCTURE (RRM Policy Ratio List -> RRM Policy Ratio Group)
  // lst_ran_param_t* RRM_Policy_Ratio_Group = &RRM_Policy_Ratio_List->ran_param_val.lst->lst_ran_param[0];
  // RRM_Policy_Ratio_Group->ran_param_id = RRM_Policy_Ratio_Group_8_4_3_6;
  RRM_Policy_Ratio_Group->ran_param_struct.sz_ran_param_struct = 4;
  RRM_Policy_Ratio_Group->ran_param_struct.ran_param_struct = calloc(4, sizeof(seq_ran_param_t));
  assert(RRM_Policy_Ratio_Group->ran_param_struct.ran_param_struct != NULL && "Memory exhausted");
  // RRM Policy, STRUCTURE (RRM Policy Ratio Group -> RRM Policy)
  seq_ran_param_t* RRM_Policy = &RRM_Policy_Ratio_Group->ran_param_struct.ran_param_struct[0];
  RRM_Policy->ran_param_id = RRM_Policy_8_4_3_6;
  RRM_Policy->ran_param_val.type = STRUCTURE_RAN_PARAMETER_VAL_TYPE;
  RRM_Policy->ran_param_val.strct = calloc(1, sizeof(ran_param_struct_t));
  assert(RRM_Policy->ran_param_val.strct != NULL && "Memory exhausted");
  RRM_Policy->ran_param_val.strct->sz_ran_param_struct = 1;
  RRM_Policy->ran_param_val.strct->ran_param_struct = calloc(1, sizeof(seq_ran_param_t));
  assert(RRM_Policy->ran_param_val.strct->ran_param_struct != NULL && "Memory exhausted");
  // RRM Policy Member List, LIST (RRM Policy -> RRM Policy Member List)
  seq_ran_param_t* RRM_Policy_Member_List = &RRM_Policy->ran_param_val.strct->ran_param_struct[0];
  RRM_Policy_Member_List->ran_param_id = RRM_Policy_Member_List_8_4_3_6;
  RRM_Policy_Member_List->ran_param_val.type = LIST_RAN_PARAMETER_VAL_TYPE;
  RRM_Policy_Member_List->ran_param_val.lst = calloc(1, sizeof(ran_param_list_t));
  assert(RRM_Policy_Member_List->ran_param_val.lst != NULL && "Memory exhausted");
  RRM_Policy_Member_List->ran_param_val.lst->sz_lst_ran_param = 1;
  RRM_Policy_Member_List->ran_param_val.lst->lst_ran_param = calloc(1, sizeof(lst_ran_param_t));
  assert(RRM_Policy_Member_List->ran_param_val.lst->lst_ran_param != NULL && "Memory exhausted");
  // RRM Policy Member, STRUCTURE (RRM Policy Member List -> RRM Policy Member)
  lst_ran_param_t* RRM_Policy_Member = &RRM_Policy_Member_List->ran_param_val.lst->lst_ran_param[0];
  // RRM_Policy_Member->ran_param_id = RRM_Policy_Member_8_4_3_6;
  RRM_Policy_Member->ran_param_struct.sz_ran_param_struct = 2;
  RRM_Policy_Member->ran_param_struct.ran_param_struct = calloc(2, sizeof(seq_ran_param_t));
  assert(RRM_Policy_Member->ran_param_struct.ran_param_struct != NULL && "Memory exhausted");
  // PLMN Identity, ELEMENT (RRM Policy Member -> PLMN Identity)
  seq_ran_param_t* PLMN_Identity = &RRM_Policy_Member->ran_param_struct.ran_param_struct[0];
  PLMN_Identity->ran_param_id = PLMN_Identity_8_4_3_6;
  PLMN_Identity->ran_param_val.type = ELEMENT_KEY_FLAG_FALSE_RAN_PARAMETER_VAL_TYPE;
  PLMN_Identity->ran_param_val.flag_false = calloc(1, sizeof(ran_parameter_value_t));
  assert(PLMN_Identity->ran_param_val.flag_false != NULL && "Memory exhausted");
  PLMN_Identity->ran_param_val.flag_false->type = OCTET_STRING_RAN_PARAMETER_VALUE;
  char plmnid_str[] = "00101";
  byte_array_t plmn_id = cp_str_to_ba(plmnid_str); // TODO
  PLMN_Identity->ran_param_val.flag_false->octet_str_ran.len = plmn_id.len;
  PLMN_Identity->ran_param_val.flag_false->octet_str_ran.buf = plmn_id.buf;
  // S-NSSAI, STRUCTURE (RRM Policy Member -> S-NSSAI)
  seq_ran_param_t* S_NSSAI = &RRM_Policy_Member->ran_param_struct.ran_param_struct[1];
  S_NSSAI->ran_param_id = S_NSSAI_8_4_3_6;
  S_NSSAI->ran_param_val.type = STRUCTURE_RAN_PARAMETER_VAL_TYPE;
  S_NSSAI->ran_param_val.strct = calloc(1, sizeof(ran_param_struct_t));
  assert(S_NSSAI->ran_param_val.strct != NULL && "Memory exhausted");
  S_NSSAI->ran_param_val.strct->sz_ran_param_struct = 2;
  S_NSSAI->ran_param_val.strct->ran_param_struct = calloc(2, sizeof(seq_ran_param_t));
  // SST, ELEMENT (S-NSSAI -> SST)
  seq_ran_param_t* SST = &S_NSSAI->ran_param_val.strct->ran_param_struct[0];
  SST->ran_param_id = SST_8_4_3_6;
  SST->ran_param_val.type = ELEMENT_KEY_FLAG_FALSE_RAN_PARAMETER_VAL_TYPE;
  SST->ran_param_val.flag_false = calloc(1, sizeof(ran_parameter_value_t));
  assert(SST->ran_param_val.flag_false != NULL && "Memory exhausted");
  SST->ran_param_val.flag_false->type = OCTET_STRING_RAN_PARAMETER_VALUE;
  // char sst_str[] = "1";
  byte_array_t sst = cp_str_to_ba(sst_str); //TODO
  SST->ran_param_val.flag_false->octet_str_ran.len = sst.len;
  SST->ran_param_val.flag_false->octet_str_ran.buf = sst.buf;
  // SD, ELEMENT (S-NSSAI -> SD)
  seq_ran_param_t* SD = &S_NSSAI->ran_param_val.strct->ran_param_struct[1];
  SD->ran_param_id = SD_8_4_3_6;
  SD->ran_param_val.type = ELEMENT_KEY_FLAG_FALSE_RAN_PARAMETER_VAL_TYPE;
  SD->ran_param_val.flag_false = calloc(1, sizeof(ran_parameter_value_t));
  assert(SD->ran_param_val.flag_false != NULL && "Memory exhausted");
  SD->ran_param_val.flag_false->type = OCTET_STRING_RAN_PARAMETER_VALUE;
  // char sd_str[] = "0";
  byte_array_t sd = cp_str_to_ba(sd_str); //TODO
  SD->ran_param_val.flag_false->octet_str_ran.len = sd.len;
  SD->ran_param_val.flag_false->octet_str_ran.buf = sd.buf;
  // Min PRB Policy Ratio, ELEMENT (RRM Policy Ratio Group -> Min PRB Policy Ratio)
  seq_ran_param_t* Min_PRB_Policy_Ratio = &RRM_Policy_Ratio_Group->ran_param_struct.ran_param_struct[1];
  Min_PRB_Policy_Ratio->ran_param_id = Min_PRB_Policy_Ratio_8_4_3_6;
  Min_PRB_Policy_Ratio->ran_param_val.type = ELEMENT_KEY_FLAG_FALSE_RAN_PARAMETER_VAL_TYPE;
  Min_PRB_Policy_Ratio->ran_param_val.flag_false = calloc(1, sizeof(ran_parameter_value_t));
  assert(Min_PRB_Policy_Ratio->ran_param_val.flag_false != NULL && "Memory exhausted");
  Min_PRB_Policy_Ratio->ran_param_val.flag_false->type = INTEGER_RAN_PARAMETER_VALUE;
  // TODO: not handle this value in OAI
  Min_PRB_Policy_Ratio->ran_param_val.flag_false->int_ran = min_ratio_prb;
  // Max PRB Policy Ratio, ELEMENT (RRM Policy Ratio Group -> Max PRB Policy Ratio)
  seq_ran_param_t* Max_PRB_Policy_Ratio = &RRM_Policy_Ratio_Group->ran_param_struct.ran_param_struct[2];
  Max_PRB_Policy_Ratio->ran_param_id = Max_PRB_Policy_Ratio_8_4_3_6;
  Max_PRB_Policy_Ratio->ran_param_val.type = ELEMENT_KEY_FLAG_FALSE_RAN_PARAMETER_VAL_TYPE;
  Max_PRB_Policy_Ratio->ran_param_val.flag_false = calloc(1, sizeof(ran_parameter_value_t));
  assert(Max_PRB_Policy_Ratio->ran_param_val.flag_false != NULL && "Memory exhausted");
  Max_PRB_Policy_Ratio->ran_param_val.flag_false->type = INTEGER_RAN_PARAMETER_VALUE;
  // TODO: not handle this value in OAI
  Max_PRB_Policy_Ratio->ran_param_val.flag_false->int_ran = max_ratio_prb;
  // Dedicated PRB Policy Ratio, ELEMENT (RRM Policy Ratio Group -> Dedicated PRB Policy Ratio)
  seq_ran_param_t* Dedicated_PRB_Policy_Ratio = &RRM_Policy_Ratio_Group->ran_param_struct.ran_param_struct[3];
  Dedicated_PRB_Policy_Ratio->ran_param_id = Dedicated_PRB_Policy_Ratio_8_4_3_6;
  Dedicated_PRB_Policy_Ratio->ran_param_val.type = ELEMENT_KEY_FLAG_FALSE_RAN_PARAMETER_VAL_TYPE;
  Dedicated_PRB_Policy_Ratio->ran_param_val.flag_false = calloc(1, sizeof(ran_parameter_value_t));
  assert(Dedicated_PRB_Policy_Ratio->ran_param_val.flag_false != NULL && "Memory exhausted");
  Dedicated_PRB_Policy_Ratio->ran_param_val.flag_false->type = INTEGER_RAN_PARAMETER_VALUE;
  Dedicated_PRB_Policy_Ratio->ran_param_val.flag_false->int_ran = dedicated_ratio_prb;

  return;
}

static void gen_rrm_policy_ratio_list(seq_ran_param_t* RRM_Policy_Ratio_List) {
    int num_slice = MAX_CLIENTS;
    RRM_Policy_Ratio_List->ran_param_id = RRM_Policy_Ratio_List_8_4_3_6;
    RRM_Policy_Ratio_List->ran_param_val.type = LIST_RAN_PARAMETER_VAL_TYPE;
    RRM_Policy_Ratio_List->ran_param_val.lst = calloc(1, sizeof(ran_param_list_t));
    assert(RRM_Policy_Ratio_List->ran_param_val.lst != NULL && "Memory exhausted");
    RRM_Policy_Ratio_List->ran_param_val.lst->sz_lst_ran_param = num_slice;
    RRM_Policy_Ratio_List->ran_param_val.lst->lst_ran_param = calloc(num_slice, sizeof(lst_ran_param_t));
    assert(RRM_Policy_Ratio_List->ran_param_val.lst->lst_ran_param != NULL && "Memory exhausted");

    // This function now reads from the global ue_data state
    for (int i = 0; i < num_slice; i++) {
        char sst_str[12]; // Increased size for safety
        char sd_str[12];
        snprintf(sst_str, sizeof(sst_str), "%d", ue_data[i].sst);
        snprintf(sd_str, sizeof(sd_str), "%d", ue_data[i].sd);
        gen_rrm_policy_ratio_group(&RRM_Policy_Ratio_List->ran_param_val.lst->lst_ran_param[i],
                                   sst_str,
                                   sd_str,
                                   0, ue_data[i].prb_allocation, 0); // Min=0, Max=0, Dedicated=our_value
    }

    return;
}



static e2sm_rc_ctrl_msg_frmt_1_t gen_rc_ctrl_msg_frmt_1_slice_level_PRB_quota() {
    e2sm_rc_ctrl_msg_frmt_1_t dst = {0};

  // 8.4.3.6
  // RRM Policy Ratio List, LIST (len 1)
  // > RRM Policy Ratio Group, STRUCTURE (len 4)
  // >>  RRM Policy, STRUCTURE (len 1)
  // >>> RRM Policy Member List, LIST (len 1)
  // >>>> RRM Policy Member, STRUCTURE (len 2)
  // >>>>> PLMN Identity, ELEMENT
  // >>>>> S-NSSAI, STRUCTURE (len 2)
  // >>>>>> SST, ELEMENT
  // >>>>>> SD, ELEMENT
  // >> Min PRB Policy Ratio, ELEMENT
  // >> Max PRB Policy Ratio, ELEMENT
  // >> Dedicated PRB Policy Ratio, ELEMENT

    // RRM Policy Ratio List, LIST
    dst.sz_ran_param = 1;
    dst.ran_param = calloc(1, sizeof(seq_ran_param_t));
    assert(dst.ran_param != NULL && "Memory exhausted");
    gen_rrm_policy_ratio_list(&dst.ran_param[0]);

    return dst;
}

static e2sm_rc_ctrl_msg_t gen_rc_ctrl_msg(e2sm_rc_ctrl_msg_e msg_frmt) {
    e2sm_rc_ctrl_msg_t dst = {0};

    if (msg_frmt == FORMAT_1_E2SM_RC_CTRL_MSG) {
        dst.format = msg_frmt;
        dst.frmt_1 = gen_rc_ctrl_msg_frmt_1_slice_level_PRB_quota();
    } else {
        assert(0!=0 && "not implemented the fill func for this ctrl msg frmt");
    }

    return dst;
}



static
ue_id_e2sm_t gen_rc_ue_id(ue_id_e2sm_e type)
{
  ue_id_e2sm_t ue_id = {0};
  if (type == GNB_UE_ID_E2SM) {
    ue_id.type = GNB_UE_ID_E2SM;
    // TODO
    ue_id.gnb.amf_ue_ngap_id = 0;
    ue_id.gnb.guami.plmn_id.mcc = 1;
    ue_id.gnb.guami.plmn_id.mnc = 1;
    ue_id.gnb.guami.plmn_id.mnc_digit_len = 2;
    ue_id.gnb.guami.amf_region_id = 0;
    ue_id.gnb.guami.amf_set_id = 0;
    ue_id.gnb.guami.amf_ptr = 0;
  } else {
    assert(0!=0 && "not supported UE ID type");
  }
  return ue_id;
}


// Function to execute RRC release command in a separate thread
void* rrc_release_ue_thread(void* arg) {
    int ran_ue_id = *((int*)arg);
    char command[256];
    // Command sends 'rrc release_rrc <id>' to the controller/simulator
    snprintf(command, sizeof(command), "echo rrc release_rrc %d | nc %s 9090", ran_ue_id, SERVER_IP);
    printf("Executing: %s\n", command);
    system(command);
    free(arg);
    return NULL;
}

// Spawns a detached thread to send the RRC release command
void rrc_release_ue(int ran_ue_id) {
    pthread_t thread;
    int* arg = malloc(sizeof(*arg));
    if (arg) {
        *arg = ran_ue_id;
        if (pthread_create(&thread, NULL, rrc_release_ue_thread, arg) != 0) {
            perror("Failed to create RRC release thread");
            free(arg);
        }
        pthread_detach(thread);  // Detach the thread to avoid memory leaks
    } else {
        perror("Failed to malloc for RRC release thread");
    }
}

// Builds and sends the E2 control message to enforce slicing
void enforce_slicing(e2_node_arr_xapp_t nodes) {
    // This function now reads the policy from the global ue_data state
    rc_ctrl_req_data_t rc_ctrl = {0};
    ue_id_e2sm_t ue_id = gen_rc_ue_id(GNB_UE_ID_E2SM);
    
    // Generate header
    rc_ctrl.hdr = gen_rc_ctrl_hdr(FORMAT_1_E2SM_RC_CTRL_HDR, ue_id, 2, Slice_level_PRB_quotal_7_6_3_1);
    
    // Generate message (which reads from global ue_data)
    rc_ctrl.msg = gen_rc_ctrl_msg(FORMAT_1_E2SM_RC_CTRL_MSG);

    printf("Enforcing new policy:\n");
    for(int i=0; i<MAX_CLIENTS; i++) {
        printf("  - Slice (SST: %d, SD: %d) -> PRB: %d%%\n", ue_data[i].sst, ue_data[i].sd, ue_data[i].prb_allocation);
    }

    // Send control message to all connected E2 nodes
    for (size_t i = 0; i < nodes.len; ++i) {
        control_sm_xapp_api(&nodes.n[i].id, SM_RC_ID, &rc_ctrl);
    }
    
    // Free the complex data structures generated for the message
    free_rc_ctrl_req_data(&rc_ctrl);
}

// Polls the database for new messages and processes them
void poll_and_process_messages(e2_node_arr_xapp_t nodes) {

    bool policy_changed = false;
    int processed_ids[256]; // Simple array to hold IDs of processed messages
    int id_count = 0;

    // Loop through all messages with status = 2
    while (sqlite3_step(select_stmt) == SQLITE_ROW) {
        int sst = sqlite3_column_int(select_stmt, 1);
        int sd = sqlite3_column_int(select_stmt, 2);
        int anomaly_count = sqlite3_column_double(select_stmt, 3);

        // Find the corresponding slice in our state array
        int ue_index = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (ue_data[i].sst == sst && ue_data[i].sd == sd) {
                ue_index = i;
                break;
            }
        }

        if (ue_index == -1) {
            fprintf(stderr, "Warning: Ignoring message for unknown slice (SST: %d, SD: %d)\n", sst, sd);
            processed_ids[id_count++] = id; // Mark as processed even if unknown
            continue;
        }

        // Determine new policy based on anomaly flag
        int new_prb_allocation = (anomaly_percentage >= 0.95) ? 0 : (int)((1.0 - anomaly_percentage) * 100);

        // Check if this new policy is different from the current one
        if (ue_data[ue_index].prb_allocation != new_prb_allocation) {
            ue_data[ue_index].prb_allocation = new_prb_allocation;
            policy_changed = true;
            printf("Policy change for Slice (SST: %d, SD: %d): Set PRB to %d%%\n", sst, sd, new_prb_allocation);
        }
        
        processed_ids[id_count++] = id; // Add to list of messages to update
        if(id_count >= 256) break; // Avoid buffer overflow if too many messages
    }
    sqlite3_reset(select_stmt);

    // If any policy changed, enforce the new policies
    if (policy_changed) {

	int total_prb_allocation = 0;
        int attacker_index = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            total_prb_allocation += ue_data[i].prb_allocation;
            if (ue_data[i].prb_allocation == 0) {
                attacker_index = i;
            }
        }

	// Don't scale if there's an attacker (let them be 0)
        // Only scale if there's no attacker AND total is over 100
        if (total_prb_allocation > 100 && attacker_index == -1) {
            printf("Total PRB (%d%%) > 100%%. Scaling down...\n", total_prb_allocation);
            double scaling_factor = 100.0 / total_prb_allocation;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                ue_data[i].prb_allocation = (int)(ue_data[i].prb_allocation * scaling_factor);
            }
        }


        // This sends the full list of policies (for all slices) to the E2 node
        enforce_slicing(nodes);

        // After enforcement, check if we need to RRC release anyone
        for (int i = 0; i < MAX_CLIENTS; i++) {
            // Check if the *newly enforced* policy is different from the *previous* one
            if (ue_data[i].prb_allocation != ue_data[i].prev_prb_allocation) {

                // If the new policy is 0%, trigger RRC release
                if (ue_data[i].prb_allocation == 0) {
                    printf("Slice (SST: %d, SD: %d) identified as anomaly. Triggering RRC release for UE %d.\n",
                           ue_data[i].sst, ue_data[i].sd, ue_data[i].rrc_ue_id);
                    rrc_release_ue(ue_data[i].rrc_ue_id);
                }

                // Update the previous allocation to match the new one
                ue_data[i].prev_prb_allocation = ue_data[i].prb_allocation;
            }
        }
    }

    // Now, update the status of all processed messages in the database
    if (id_count > 0) {
        printf("Processing %d messages from database...\n", id_count);

        for (int i = 0; i < id_count; i++) {
            sqlite3_bind_int(update_stmt, 1, processed_ids[i]);
            if (sqlite3_step(update_stmt) != SQLITE_DONE) {
                fprintf(stderr, "Failed to update message ID %d: %s\n", processed_ids[i], sqlite3_errmsg(db));
            }
            sqlite3_reset(update_stmt); // Reset for next iteration
        }
        printf("Finished processing %d messages.\n", id_count);
    }
}


int main(int argc, char *argv[]) {
    char *err_msg = 0;

    // --- Initialize SQLite Database ---
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    puts("Database opened successfully.");

    // Create the table as requested if it doesn't exist
    const char *sql_create_table = 
        "CREATE TABLE IF NOT EXISTS messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "sst INTEGER NOT NULL,"
        "sd INTEGER NOT NULL,"
        "encrypted_input BLOB,"
	"encrypted_prediction_result BLOB,"
        "anomaly_percentage REAL,"
        "status INTEGER NOT NULL,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    if (sqlite3_exec(db, sql_create_table, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "Failed to create table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }
    puts("Table 'messages' is ready.");

    // --- Prepare SQL statements ONCE ---
    const char *sql_select = "SELECT t.sst, t.sd, SUM(t.anomaly_percentage) FROM (SELECT sst, sd, anomaly_percentage from messages WHERE status = 2 ORDER BY timestamp DESC LIMIT 30) as t GROUP BY t.sst, t.sd ;";
    if (sqlite3_prepare_v2(db, sql_select, -1, &select_stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare select statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    const char *sql_update = "UPDATE messages SET status = 3 WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql_update, -1, &update_stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(select_stmt); // Clean up the one that succeeded
        sqlite3_close(db);
        return 1;
    }
    puts("SQL statements prepared successfully.");

    // --- Initialize xApp ---
    fr_args_t args = init_fr_args(argc, argv);
    //defer({ free_fr_args(&args); });

    // Init the xApp
    init_xapp_api(&args);
    sleep(1);

    e2_node_arr_xapp_t nodes = e2_nodes_xapp_api();
    defer({ free_e2_node_arr_xapp(&nodes); });
    if (nodes.len == 0) {
        fprintf(stderr, "No E2 nodes connected. Exiting.\n");
        sqlite3_close(db);
        return 1;
    }
    printf("Connected E2 nodes = %d\n", nodes.len);


    // --- Initialize Slice State ---
    // This xApp is hardcoded to manage two specific slices
    // Slice 1: SST=1, SD=1
    ue_data[0].sst = 1;
    ue_data[0].sd = 1;
    ue_data[0].prb_allocation = 50; // Default to 50%
    ue_data[0].prev_prb_allocation = 50;
    ue_data[0].rrc_ue_id = 1; // Mapped UE ID for RRC release

    // Slice 2: SST=1, SD=5
    ue_data[1].sst = 1;
    ue_data[1].sd = 5;
    ue_data[1].prb_allocation = 50; // Default to 50%
    ue_data[1].prev_prb_allocation = 50;
    ue_data[1].rrc_ue_id = 2; // Mapped UE ID for RRC release
    

    ////////////
    // START RC
    ////////////

    // RC Control
    // CONTROL Service Style 2: Radio Resource Allocation Control
    // Action ID 6: Slice-level PRB quota
    // E2SM-RC Control Header Format 1
    // E2SM-RC Control Message Format 1
    
    // Send initial default allocation (50/50)
    puts("Sending initial 50/50 PRB allocation...");
    enforce_slicing(nodes);
    puts("RC initialization completed. Starting main loop...");

    // --- Main loop ---
    // This loop periodically polls the database for new messages
    while (1) {
        poll_and_process_messages(nodes);
        usleep(POLLING_INTERVAL_US); // Wait for the next polling interval
    }

    while (try_stop_xapp_api() == false) {
        usleep(1000); // Wait for the next polling interval
    }
    // --- Cleanup ---
    sqlite3_finalize(select_stmt);
    sqlite3_finalize(update_stmt);
    puts("Prepared statements finalized.");
    sqlite3_close(db);
    puts("Database closed.");

    ////////////
    // END RC
    ////////////

    //Stop the xApp (already handled by while loop condition)
    puts("Stopping xApp...");

    return 0;
}
