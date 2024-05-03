# Windows Copilot
A repo containing information on the use of Windows Copilot, in countries where the functionality has not been released yet by Microsoft

## Introduction
Microsoft has released a lot of Copilot integration, one of which is called 'Windows Copilot' (also kown as 'Copilot in Windows'). Unfortunately, Microsoft has not yet released Windows Copilot in the EU, proabably as they cannot yet commit to the EU Data Privacy regulations. However as a technical enthousiast, I did want to experiment with Windows Copilot and thereby had to gain access to it next to my existing access to other Copilot experiences. I've done a little bit of research on the internet followed by trial-and-error to enable the feature.

The result of that work is captured in a single PowerShell script that can be used to enable Windows Copilot.

My work is standalone, without any affliation to my employer and comes any warranty on its functions. This particular script makes changes to a (or more) file(s) in ```C:\Windows\System32``` and the ```Registry```. As always, take caution and care when running someone else's script - understand what the code does and ensure you have back-ups where applicable.

## How to use?
To run it, just run through these instructions after reading the code itself so you're aware of what it will do to your system. Create back-ups of files and Windows registry where applicable.

To use this script, you need to run it with administrator privileges. You can do this by right-clicking on the PowerShell icon and selecting "Run as administrator".

Then navigate to the script's location, below example would navigate to the Downloads folder (assuming standard location) \
```Set-Location (Join-Path -Path $HOME -Child "Downloads")```

It might also be required to bypass the execution policy preventing the run of any unsigned / untrusted script. The following cmdlet can service this for the current process (only) \
```Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process```

Assuming you've read, understood and confirmed the code in the script. Run the script as below to unlock Copilot for Windows for NL - replace NL with any other ISO 3166-1 alpha-2 code representation \
```.\Enable-WindowsCopilot.ps1 -UnlockCountry NL```

## What did I do?
Through common tools like SysInternals (ProcMon, ProcExplorer) I was able to find specific registry keys retrieved from the registry and a file being 'read' whenever I tried launching Copilot for Windows in a region where it is allowed and where it isn't allowed. One of the things found in my 'non working environment' was a reference to a registry key ```CopilotDisabledReason``` with a value of ```IsEnabledForGeographicRegionFailed```, emphasis on the **failed**. This alongside my own research led me to a [Microsoft Community forum post](https://techcommunity.microsoft.com/t5/copilot-for-microsoft-365/access-to-quot-copilot-in-window-preview-quot-via-the-taskbar/m-p/4115310) discussing the JSON-file to some extend.

Fast forward - combining my own findings with what I could find on the internet, allowed me to get the 'Copilot (Preview)' feature available in the Windows Taskbar settings. I've wrapped all my stuff into a single PowerShell script, obviously using Github Copilot to speed up the coding work. I'm hoping this work can enable other tech. enthousiasts to also start expirimenting with Windows Copilot whilst we patiently await its initial release within the EU.

## What can you do?
The current code is really a quick-and-dirty and can probably benefit from your improvements - please feel free to submit them!

## License
See [LICENSE](LICENSE), the code found in this repository is provided as-is under the MIT license

## Links
A list of usefull links
- [Copilot in Windows & Other | Microsoft ](https://www.microsoft.com/en-us/windows/copilot-ai-features#faq)
- [Sysinternals | Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/)
