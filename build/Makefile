all: copy update_git

copy:
	cd "Marionette Bootstrap" && xcodebuild
	for i in "/Volumes/Marionette Cache"*/"Marionette Bootstrap.app" ; do \
		rsync -avp --delete "./Marionette Bootstrap/build/Release/Marionette Bootstrap.app/" "$$i"; \
	done

update_git:
	for i in "/Volumes/Marionette Cache"*/"git" ; do \
		"$$i"/update & \
	done; wait

eject:
	for i in "/Volumes/Marionette Cache"*/ ; do \
		diskutil eject "$$i"; \
	done
