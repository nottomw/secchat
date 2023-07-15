# Secchat "modes" to control terminal/TUI/...

function(secchat_mode_verify)
    set(SECCHAT_MODES_AVAILABLE terminal ncurses)

    if (NOT SECCHAT_MODE)
        message(FATAL_ERROR "SECCHAT_MODE must be set to one of modes: ${SECCHAT_MODES_AVAILABLE}")
    endif()

    list(FIND SECCHAT_MODES_AVAILABLE ${SECCHAT_MODE} IDX)
    if(IDX EQUAL -1)
        message(FATAL_ERROR "secchat mode must be one of valid modes: ${SECCHAT_MODES_AVAILABLE}")
    endif()

    message(INFO "setting secchat to ${SECCHAT_MODE} mode")
endfunction()
