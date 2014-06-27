copy:
	cd "Marionette Bootstrap" && xcodebuild
	for i in "/Volumes/Marionette Cache"*/"Marionette Bootstrap.app" ; do \
		rsync -avp --delete "./Marionette Bootstrap/build/Release/Marionette Bootstrap.app/" "$$i"; \
	done

eject:
	for i in "/Volumes/Marionette Cache"*/ ; do \
		diskutil eject "$$i"; \
	done
