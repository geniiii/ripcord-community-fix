# ripcord-community-fix
*(formerly known as `ripcord-audio-hook`)*

Fixes Ripcord:
1. not connecting <sup>due to the binary ETF parser aborting upon discovering invalid/unhandled map keys</sup>
2. lacking support for new encryption modes, causing it to fail to connect to voice channels
3. having garbled audio in voice channels <sup>due to reading RTP header extensions larger than 8 bytes as voice data</sup>
4. getting stuck on "Routing..." when attempting to join voice channels <sup>due to sending and receiving an old (?) version of the IP discovery packet</sup>
5. failing to connect to voice channels <sup>due to creating malformed WebSocket gateway URIs</sup>
6. not ordering servers in the sidebar correctly <sup>due to the addition of folders</sup>
7. not loading image previews
8. not showing "Stage" voice channels  
   *(This is accomplished by making Ripcord think stages are regular voice channels. This means that there is no way to become a speaker, and no way to differentiate a stage from a regular voice channel)*

Supports Ripcord 0.4.29 on Windows. [Supports Ripcord 0.4.29 on Linux, albeit with limited testing.](https://github.com/geniiii/ripcord-audio-hook/tree/linux)

## Usage
Download the DLL file from [the Releases page](https://github.com/geniiii/ripcord-audio-hook/releases) and place it in your Ripcord directory, or watch the video below if you don't understand:  
<a href="https://www.youtube.com/watch?v=KwhXPrJ05Rw"><img src="https://github.com/user-attachments/assets/16c1caf4-0f1c-4c98-9c31-ffc916504717" width=640px></a>

## Building
### If you don't know what you're doing, look at the Usage section above instead.
1. Install Visual Studio 2019 or newer with the C++ development tools
2. Run `build.bat`

## Credits
[@u130b8](https://github.com/u130b8) for fixing image previews  
[@ouwou](https://github.com/ouwou) for determining the cause of garbled audio  
[@muffinl0rd](https://github.com/muffinl0rd) for bypassing ETF parser abortion
