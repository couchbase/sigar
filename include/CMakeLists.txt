IF (INSTALL_HEADER_FILES)
INSTALL(FILES sigar.h
	sigar_fileinfo.h
	sigar_format.h
	sigar_getline.h
	sigar_log.h
	sigar_private.h
	sigar_ptql.h
	sigar_util.h
        sigar_visibility.h
	DESTINATION include/
	)
ENDIF (INSTALL_HEADER_FILES)
