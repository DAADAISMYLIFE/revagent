| challenge | flag |
|---|---|
| xor_check | DH{x0r_m1n1_ch3ck} |
| vm_loop | DH{vm_l00p_tr4ce} |
| win_console | DH{w1ne_c0ns0le} |
| win_gui | DH{gui_p41nt_0k} |
| win_gui_key | DH{k3y_dr1v3n_ui} |
| win_gui_32 | DH{w1n32_runb00k} |

win_gui_32 is a PE32 the image cannot run (wine64 only): the expected outcome is status `runbook`, or `solved` by a static XOR decode. `check_answer` reads the flag cell verbatim, so that note must not live in the table.
