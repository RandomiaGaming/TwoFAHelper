# How To Build And Run
To build and run this program you have three options depending on your preferences:

1. Download the latest pre-built binary from the releases tab of this project on GitHub
[https://github.com/RandomiaGaming/TwoFAHelper](https://github.com/RandomiaGaming/TwoFAHelper)

2. Compile it yourself by first cloning the repo then opening the .sln file in Visual Studio and compiling the project.
I recommend using Visual Studio 2022 community edition with the .Net desktop development pack in Release mode for x64 as that is the build configuration I have tested.
However other configurations on other versions of Visual Studio should also work.

3. If you really want to do everything yourself you can copy Program.cs from this repo into a new c# project and build it yourself.
I recommend using .Net framework version 4.8.1 as that's what I used. Additionally this project depends on the QRCoder NuGet package.
It has no other dependencies or special settings and the code is designed to be portable and easy to compile.