# libkrb5 API coverage

This document lists all public functions from the upstream API documentation for
MIT `libkrb5` (for which there are generated, `unsafe` Rust bindings in the
`libkrb5-sys` crate) and their equivalent safe Rust wrappers as implemented in
the `libkrb5` crate.

See: <https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/index.html>

## Frequently used public interfaces

### Already wrapped in libkrb5

| C function                        | Rust equivalent                       | Notes                         |
| --------------------------------- | ------------------------------------- | ----------------------------- |
| `krb5_build_principal`            | `Krb5Context.build_principal`         |                               |
| `krb5_build_principal_alloc_va`   | `Krb5Context.build_principal`         | no `va_list` support in Rust  |
| `krb5_build_principal_ext`        | `Krb5Context.build_principal`         |                               |
| `krb5_cc_close`                   | `Krb5CCache.drop`                     | in `impl Drop`                |
| `krb5_cc_default`                 | `Krb5CCache::default`                 |                               |
| `krb5_cc_default_name`            | `Krb5CCache::default_name`            |                               |
| `krb5_cc_destroy`                 | `Krb5CCache.destroy`                  |                               |
| `krb5_cc_dup`                     | `Krb5CCache.dup`                      |                               |
| `krb5_cc_get_name`                | `Krb5CCache.get_name`                 |                               |
| `krb5_cc_get_principal`           | `Krb5CCache.get_principal`            |                               |
| `krb5_cc_get_type`                | `Krb5CCache.get_type`                 |                               |
| `krb5_cc_initialize`              | `Krb5CCache.initialize`               |                               |
| `krb5_cc_new_unique`              | `Krb5CCache::new_unique`              |                               |
| `krb5_cc_resolve`                 | `Krb5CCache::resolve`                 |                               |
| `krb5_free_context`               | `Krb5Context.drop`                    | in `impl Drop`                |
| `krb5_free_error_message`         | `Krb5Context.error_code_to_message`   | used only internally          |
| `krb5_free_principal`             | `Krb5Principal.drop`                  | in `impl Drop`                |
| `krb5_get_default_realm`          | `Krb5Context.get_default_realm`       |                               |
| `krb5_get_error_message`          | `Krb5Context.error_code_to_message`   | used only internally          |
| `krb5_get_host_realm`             | `Krb5Context.get_host_realms`         |                               |
| `krb5_init_context`               | `Krb5Context::init`                   |                               |
| `krb5_init_secure_context`        | `Krb5Context::init_secure`            |                               |

### Present in libkrb5-sys but not yet wrapped in libkrb5

- `krb5_change_password`
- `krb5_chpw_message`
- `krb5_expand_hostname`
- `krb5_fwd_tgt_creds`
- `krb5_get_credentials`
- `krb5_get_fallback_host_realm`
- `krb5_get_init_creds_keytab`
- `krb5_get_init_creds_opt_alloc`
- `krb5_get_init_creds_opt_free`
- `krb5_get_init_creds_opt_get_fast_flags`
- `krb5_get_init_creds_opt_set_address_list`
- `krb5_get_init_creds_opt_set_anonymous`
- `krb5_get_init_creds_opt_set_canonicalize`
- `krb5_get_init_creds_opt_set_change_password_prompt`
- `krb5_get_init_creds_opt_set_etype_list`
- `krb5_get_init_creds_opt_set_expire_callback`
- `krb5_get_init_creds_opt_set_fast_ccache`
- `krb5_get_init_creds_opt_set_fast_ccache_name`
- `krb5_get_init_creds_opt_set_fast_flags`
- `krb5_get_init_creds_opt_set_forwardable`
- `krb5_get_init_creds_opt_set_in_ccache`
- `krb5_get_init_creds_opt_set_out_ccache`
- `krb5_get_init_creds_opt_set_pa`
- `krb5_get_init_creds_opt_set_pac_request`
- `krb5_get_init_creds_opt_set_preauth_list`
- `krb5_get_init_creds_opt_set_proxiable`
- `krb5_get_init_creds_opt_set_renew_life`
- `krb5_get_init_creds_opt_set_responder`
- `krb5_get_init_creds_opt_set_salt`
- `krb5_get_init_creds_opt_set_tkt_life`
- `krb5_get_init_creds_password`
- `krb5_get_profile`
- `krb5_get_prompt_types`
- `krb5_get_renewed_creds`
- `krb5_get_validated_creds`
- `krb5_is_config_principal`
- `krb5_is_thread_safe`
- `krb5_kt_close`
- `krb5_kt_client_default`
- `krb5_kt_default`
- `krb5_kt_default_name`
- `krb5_kt_dup`
- `krb5_kt_get_name`
- `krb5_kt_get_type`
- `krb5_kt_resolve`
- `krb5_kuserok`
- `krb5_parse_name`
- `krb5_parse_name_flags`
- `krb5_principal_compare`
- `krb5_principal_compare_any_realm`
- `krb5_principal_compare_flags`
- `krb5_prompter_posix`
- `krb5_realm_compare`
- `krb5_responder_get_challenge`
- `krb5_responder_list_questions`
- `krb5_responder_set_answer`
- `krb5_responder_otp_get_challenge`
- `krb5_responder_otp_set_answer`
- `krb5_responder_otp_challenge_free`
- `krb5_responder_pkinit_get_challenge`
- `krb5_responder_pkinit_set_answer`
- `krb5_responder_pkinit_challenge_free`
- `krb5_set_default_realm`
- `krb5_set_password`
- `krb5_set_password_using_ccache`
- `krb5_set_principal_realm`
- `krb5_set_trace_callback`
- `krb5_set_trace_filename`
- `krb5_sname_match`
- `krb5_sname_to_principal`
- `krb5_unparse_name`
- `krb5_unparse_name_ext`
- `krb5_unparse_name_flags`
- `krb5_unparse_name_flags_ext`
- `krb5_us_timeofday`
- `krb5_verify_authdata_kdc_issued`

## Rarely used public interfaces

### Already wrapped in libkrb5

| C function                        | Rust equivalent                       | Notes                         |
| --------------------------------- | ------------------------------------- | ----------------------------- |
| `krb5_free_host_realm`            | N/A                                   | used only internally          | 

### Present in libkrb5-sys but not yet wrapped in libkrb5

- `krb5_425_conv_principal`
- `krb5_524_conv_principal`
- `krb5_address_compare`
- `krb5_address_order`
- `krb5_address_search`
- `krb5_allow_weak_crypto`
- `krb5_aname_to_localname`
- `krb5_anonymous_principal`
- `krb5_anonymous_realm`
- `krb5_appdefault_boolean`
- `krb5_appdefault_string`
- `krb5_auth_con_free`
- `krb5_auth_con_genaddrs`
- `krb5_auth_con_get_checksum_func`
- `krb5_auth_con_getaddrs`
- `krb5_auth_con_getauthenticator`
- `krb5_auth_con_getflags`
- `krb5_auth_con_getkey`
- `krb5_auth_con_getkey_k`
- `krb5_auth_con_getlocalseqnumber`
- `krb5_auth_con_getrcache`
- `krb5_auth_con_getrecvsubkey`
- `krb5_auth_con_getrecvsubkey_k`
- `krb5_auth_con_getremoteseqnumber`
- `krb5_auth_con_getsendsubkey`
- `krb5_auth_con_getsendsubkey_k`
- `krb5_auth_con_init`
- `krb5_auth_con_set_checksum_func`
- `krb5_auth_con_set_req_cksumtype`
- `krb5_auth_con_setaddrs`
- `krb5_auth_con_setflags`
- `krb5_auth_con_setports`
- `krb5_auth_con_setrcache`
- `krb5_auth_con_setrecvsubkey`
- `krb5_auth_con_setrecvsubkey_k`
- `krb5_auth_con_setsendsubkey`
- `krb5_auth_con_setsendsubkey_k`
- `krb5_auth_con_setuseruserkey`
- `krb5_cc_cache_match`
- `krb5_cc_copy_creds`
- `krb5_cc_end_seq_get`
- `krb5_cc_get_config`
- `krb5_cc_get_flags`
- `krb5_cc_get_full_name`
- `krb5_cc_move`
- `krb5_cc_next_cred`
- `krb5_cc_remove_cred`
- `krb5_cc_retrieve_cred`
- `krb5_cc_select`
- `krb5_cc_set_config`
- `krb5_cc_set_default_name`
- `krb5_cc_set_flags`
- `krb5_cc_start_seq_get`
- `krb5_cc_store_cred`
- `krb5_cc_support_switch`
- `krb5_cc_switch`
- `krb5_cccol_cursor_free`
- `krb5_cccol_cursor_new`
- `krb5_cccol_cursor_next`
- `krb5_cccol_have_content`
- `krb5_clear_error_message`
- `krb5_check_clockskew`
- `krb5_copy_addresses`
- `krb5_copy_authdata`
- `krb5_copy_authenticator`
- `krb5_copy_checksum`
- `krb5_copy_context`
- `krb5_copy_creds`
- `krb5_copy_data`
- `krb5_copy_error_message`
- `krb5_copy_keyblock`
- `krb5_copy_keyblock_contents`
- `krb5_copy_principal`
- `krb5_copy_ticket`
- `krb5_find_authdata`
- `krb5_free_addresses`
- `krb5_free_ap_rep_enc_part`
- `krb5_free_authdata`
- `krb5_free_authenticator`
- `krb5_free_cred_contents`
- `krb5_free_creds`
- `krb5_free_data`
- `krb5_free_data_contents`
- `krb5_free_default_realm`
- `krb5_free_enctypes`
- `krb5_free_error`
- `krb5_free_keyblock`
- `krb5_free_keyblock_contents`
- `krb5_free_keytab_entry_contents`
- `krb5_free_string`
- `krb5_free_ticket`
- `krb5_free_unparsed_name`
- `krb5_get_etype_info`
- `krb5_get_permitted_enctypes`
- `krb5_get_server_rcache`
- `krb5_get_time_offsets`
- `krb5_init_context_profile`
- `krb5_init_creds_free`
- `krb5_init_creds_get`
- `krb5_init_creds_get_creds`
- `krb5_init_creds_get_error`
- `krb5_init_creds_get_times`
- `krb5_init_creds_init`
- `krb5_init_creds_set_keytab`
- `krb5_init_creds_set_password`
- `krb5_init_creds_set_service`
- `krb5_init_creds_step`
- `krb5_init_keyblock`
- `krb5_is_referral_realm`
- `krb5_kt_add_entry`
- `krb5_kt_end_seq_get`
- `krb5_kt_get_entry`
- `krb5_kt_have_content`
- `krb5_kt_next_entry`
- `krb5_kt_read_service_key`
- `krb5_kt_remove_entry`
- `krb5_kt_start_seq_get`
- `krb5_make_authdata_kdc_issued`
- `krb5_merge_authdata`
- `krb5_mk_1cred`
- `krb5_mk_error`
- `krb5_mk_ncred`
- `krb5_mk_priv`
- `krb5_mk_rep`
- `krb5_mk_rep_dce`
- `krb5_mk_req`
- `krb5_mk_req_extended`
- `krb5_mk_safe`
- `krb5_os_localaddr`
- `krb5_pac_add_buffer`
- `krb5_pac_free`
- `krb5_pac_get_buffer`
- `krb5_pac_get_types`
- `krb5_pac_init`
- `krb5_pac_parse`
- `krb5_pac_sign`
- `krb5_pac_sign_ext`
- `krb5_pac_verify`
- `krb5_pac_verify_ext`
- `krb5_pac_get_client_info`
- `krb5_prepend_error_message`
- `krb5_principal2salt`
- `krb5_rd_cred`
- `krb5_rd_error`
- `krb5_rd_priv`
- `krb5_rd_rep`
- `krb5_rd_rep_dce`
- `krb5_rd_req`
- `krb5_rd_safe`
- `krb5_read_password`
- `krb5_salttype_to_string`
- `krb5_server_decrypt_ticket_keytab`
- `krb5_set_default_tgs_enctypes`
- `krb5_set_error_message`
- `krb5_set_kdc_recv_hook`
- `krb5_set_kdc_send_hook`
- `krb5_set_real_time`
- `krb5_string_to_cksumtype`
- `krb5_string_to_deltat`
- `krb5_string_to_enctype`
- `krb5_string_to_salttype`
- `krb5_string_to_timestamp`
- `krb5_timeofday`
- `krb5_timestamp_to_sfstring`
- `krb5_timestamp_to_string`
- `krb5_tkt_creds_free`
- `krb5_tkt_creds_get`
- `krb5_tkt_creds_get_creds`
- `krb5_tkt_creds_get_times`
- `krb5_tkt_creds_init`
- `krb5_tkt_creds_step`
- `krb5_verify_init_creds`
- `krb5_verify_init_creds_opt_init`
- `krb5_verify_init_creds_opt_set_ap_req_nofail`
- `krb5_vprepend_error_message`
- `krb5_vset_error_message`
- `krb5_vwrap_error_message`
- `krb5_wrap_error_message`

## Public interfaces that should not be called directly

### Present in libkrb5-sys but not yet wrapped in libkrb5

- `krb5_c_block_size`
- `krb5_c_checksum_length`
- `krb5_c_crypto_length`
- `krb5_c_crypto_length_iov`
- `krb5_c_decrypt`
- `krb5_c_decrypt_iov`
- `krb5_c_derive_prfplus`
- `krb5_c_encrypt`
- `krb5_c_encrypt_iov`
- `krb5_c_encrypt_length`
- `krb5_c_enctype_compare`
- `krb5_c_free_state`
- `krb5_c_fx_cf2_simple`
- `krb5_c_init_state`
- `krb5_c_is_coll_proof_cksum`
- `krb5_c_is_keyed_cksum`
- `krb5_c_keyed_checksum_types`
- `krb5_c_keylengths`
- `krb5_c_make_checksum`
- `krb5_c_make_checksum_iov`
- `krb5_c_make_random_key`
- `krb5_c_padding_length`
- `krb5_c_prf`
- `krb5_c_prfplus`
- `krb5_c_prf_length`
- `krb5_c_random_add_entropy`
- `krb5_c_random_make_octets`
- `krb5_c_random_os_entropy`
- `krb5_c_random_to_key`
- `krb5_c_string_to_key`
- `krb5_c_string_to_key_with_params`
- `krb5_c_valid_cksumtype`
- `krb5_c_valid_enctype`
- `krb5_c_verify_checksum`
- `krb5_c_verify_checksum_iov`
- `krb5_cksumtype_to_string`
- `krb5_decode_authdata_container`
- `krb5_decode_ticket`
- `krb5_deltat_to_string`
- `krb5_encode_authdata_container`
- `krb5_enctype_to_name`
- `krb5_enctype_to_string`
- `krb5_free_checksum`
- `krb5_free_checksum_contents`
- `krb5_free_cksumtypes`
- `krb5_free_tgt_creds`
- `krb5_k_create_key`
- `krb5_k_decrypt`
- `krb5_k_decrypt_iov`
- `krb5_k_encrypt`
- `krb5_k_encrypt_iov`
- `krb5_k_free_key`
- `krb5_k_key_enctype`
- `krb5_k_key_keyblock`
- `krb5_k_make_checksum`
- `krb5_k_make_checksum_iov`
- `krb5_k_prf`
- `krb5_k_reference_key`
- `krb5_k_verify_checksum`
- `krb5_k_verify_checksum_iov`

## Legacy convenience interfaces

### Present in libkrb5-sys but not yet wrapped in libkrb5

- `krb5_recvauth`
- `krb5_recvauth_version`
- `krb5_sendauth`

## Deprecated public interfaces

### Present in libkrb5-sys but not yet wrapped in libkrb5

- `krb5_524_convert_creds`
- `krb5_auth_con_getlocalsubkey`
- `krb5_auth_con_getremotesubkey`
- `krb5_auth_con_initivector`
- `krb5_build_principal_va`
- `krb5_c_random_seed`
- `krb5_calculate_checksum`
- `krb5_checksum_size`
- `krb5_encrypt`
- `krb5_decrypt`
- `krb5_eblock_enctype`
- `krb5_encrypt_size`
- `krb5_finish_key`
- `krb5_finish_random_key`
- `krb5_cc_gen_new`
- `krb5_get_credentials_renew`
- `krb5_get_credentials_validate`
- `krb5_get_in_tkt_with_password`
- `krb5_get_in_tkt_with_skey`
- `krb5_get_in_tkt_with_keytab`
- `krb5_get_init_creds_opt_init`
- `krb5_init_random_key`
- `krb5_kt_free_entry`
- `krb5_random_key`
- `krb5_process_key`
- `krb5_string_to_key`
- `krb5_use_enctype`
- `krb5_verify_checksum`

