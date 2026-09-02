# what is this?

super epic api for JESSI resource packs, a feature that literally NOBODY will ever even use!!! I spent like 2 days working on this shit!!!

# can I run this myself?

I guess? theres no real reason to tho, you'd have to also go and manually change the hardcoded values in the JESSI app source code (or build your own app that just so happens to also need an api that does this)

if you wanna host it yourself, literally just drag and drop it into an apache webroot with php installed and you're good to go. if that doesn't work, go ask your favorite ai model for support

# why is this shit even open source?

imo its just good practice to keep something like this open source, it would be wrong for me to claim "hey guys this feature is perfectly safe and fine to use!" if people couldn't yk, verify that its actually secure

# how do can I trust that you're not spying on my super private proprietary resource packs?

technically I could if I were so inclined, but the api is set up in a way that makes it a pain in the ass for me to do so. if there were a way to set it up so that I genuinely couldnt read your data, I would set it up that way. unfortunately though I dont know of any ways to do this

that being said, all uploaded files only persist while the JESSI server is actually online, and the files are encrypted. this means that I cant just go log into my webserver with sftp and download the files whenever I want. if I wanted to get the data, I would have to go and look at the apache logs, download your resource packs blob.bin, then decrypt it with the key. would I ever actually do this? FUCK NO. it would be morally wrong for me to do so, and I literally gain nothing from doing it. my word probably means nothing to you though, so if you dont want to use this service because I, baconmania, could in theory look at your resource pack, then so be it. no skin off my ass
## if you can think of any way to make this more secure, please reach out to me and let me know or make a pull request!
