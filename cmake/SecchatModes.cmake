# Secchat "modes" to control terminal/TUI/...

function(secchat_mode_set MODE)
    set(SECCHAT_MODES_AVAILABLE terminal ncurses)

    list(FIND SECCHAT_MODES_AVAILABLE ${MODE} IDX)
    if(IDX EQUAL -1)
        message(FATAL_ERROR "secchat mode must be one of valid modes: ${SECCHAT_MODES_AVAILABLE}")
    endif()

    message(INFO "setting secchat to ${MODE} mode")

    set(SECCHAT_MODE "${MODE}" PARENT_SCOPE)
endfunction()
