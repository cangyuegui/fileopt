# fileopt

CC=/Volumes/Storage/AndroidNDK12479018.app/Contents/NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android29-clang CXX=/Volumes/Storage/AndroidNDK12479018.app/Contents/NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android29-clang++ GOOS=android GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o android_webdav_android_x86_64 main.go