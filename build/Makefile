all: copy update_git update_cache

build:
	cd "Marionette Bootstrap" && xcodebuild

copy: build init_usbdrive
	for i in "/Volumes/Marionette Cache"*/"Marionette Bootstrap.app" ; do \
		rsync -avp --delete "./Marionette Bootstrap/build/Release/Marionette Bootstrap.app/" "$$i"; \
	done

update_git: init_usbdrive
	for i in "/Volumes/Marionette Cache"*/"git" ; do \
		( ! [ -x "$$i"/git/update ] && ./git/bootstrap.sh "$$i" ; \
		"$$i"/update) & \
	done; wait

update_cache: init_usbdrive
	(cd cache && \
	for file in * ; do \
		../bin/cache-file "$$file" "/Volumes/Marionette Cache"* ; \
	done)

init_usbdrive:
	for target in "/Volumes/Marionette Cache"*/ ; do \
		mkdir -p "$$target"/{git,"Marionette Bootstrap.app",stripe-marionette} ; \
	done

eject:
	for i in "/Volumes/Marionette Cache"*/ ; do \
		diskutil eject "$$i"; \
	done
