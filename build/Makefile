all: copy update_git update_cache

copy:
	cd "Marionette Bootstrap" && xcodebuild
	for i in "/Volumes/Marionette Cache"*/"Marionette Bootstrap.app" ; do \
		rsync -avp --delete "./Marionette Bootstrap/build/Release/Marionette Bootstrap.app/" "$$i"; \
	done

update_git:
	for i in "/Volumes/Marionette Cache"*/"git" ; do \
		"$$i"/update & \
	done; wait

update_cache:
	(cd cache && \
	for file in * ; do \
		../bin/cache-file "$$file" "/Volumes/Marionette Cache"* ; \
	done)

eject:
	for i in "/Volumes/Marionette Cache"*/ ; do \
		diskutil eject "$$i"; \
	done
