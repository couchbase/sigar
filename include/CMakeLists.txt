IF (INSTALL_HEADER_FILES)
INSTALL(FILES sigar.h
	sigar_format.h
	sigar_log.h
	sigar_private.h
	sigar_util.h
    sigar_visibility.h
    sigar_control_group.h
	DESTINATION include/
	)
ENDIF (INSTALL_HEADER_FILES)
