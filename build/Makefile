copy:
	cd "Marionette Bootstrap" && xcodebuild
	rsync -avp --delete "Marionette Bootstrap/build/Release/Marionette Bootstrap.app" "/Volumes/Marionette Cache"

eject:
	diskutil eject '/Volumes/Marionette Cache'
