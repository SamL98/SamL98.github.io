---
layout: post
title:  "Creating Spotify Album Art Collages with PCA"
date:   2020-04-10 18:12:10 -0500
categories: jekyll update
---

In this post, I'll be explaining how I created this collage of album art:

![collage](/images/collage.png)

## Getting the Data

As with any machine learning task, we need a good source of data. The data for this task would be my unfiltered Spotify listening history. That's great. Spotify even has an [API endpoint] for it. There only problem is you can only get the past 50 listened to songs.

This is not good. 50 is way too low to a number to base our algorithm on. We need on the order of thousands, maybe even tens of thousands of songs if we want a shot at this.

I came up with a solution to this. It's not the best but with some patience, it just might work.

## Setting up the Cron Job

Since we can only get the most recent 50 songs, why not just repeatedly poll the API to increase our dataset size? While far from ideal, this will work fine. But now another problem arises: I'll never remember to consistently poll the API. However, no fear! Cron saves the day!

If we set up a cron job to run at specified intervals, we will never have to remember to poll the API and our treasure trove of listening history will keep growing; all we have to do is listen!

I've put the python script I use for this into a [gist] for anyone to take a look at. One thing to note is the use of the `sputil` module. This is a module I wrote a long time ago to deal with the Spotify API and OAuth. I've created a [sputil gist] if you want to take a look. I may publish to full module in the future but right now it is full of hacky, year-old code.

Now all we have to do run this script as a cron job:

```bash
script_path=<redacted>
python_path=/Library/Frameworks/Python.framework/Versions/3.6/bin/python3
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin

0 8 * * * cd $script_path && $python_path get_recents.py >> $script_path/cron_log.log
0 12 * * * cd $script_path && $python_path get_recents.py >> $script_path/cron_log.log
0 16 * * * cd $script_path && $python_path get_recents.py >> $script_path/cron_log.log
0 20 * * * cd $script_path && $python_path get_recents.py >> $script_path/cron_log.log
0 23 * * * cd $script_path && $python_path get_recents.py >> $script_path/cron_log.log
``` 

This job is set to run at 4 hour intervals every day, starting at 8:00 am. I'm not sure if the changes to `PATH` are still needed but I remember I had a lot of trouble getting this job to actually run and I believe that fixed it.

I first created this job last May, ran it for a little, gathered a hundred songs, and then something broke and this project went to the backburner. A few weeks ago I dug this project up from the graveyard, started running this job again, and now I have a little over 2500 songs in `recently_played.csv`. Not quite as much as I'd like, but it's a start.

## Creating the Graph

Now that we have a decent dataset of songs, we need a way to create a graph of similar songs if we are going to perform graph clustering (duh!). To do this, we will first need to split the listening history into sessions.

*What is a session?* A session is a string of songs in our history file that were listened to in the same sitting. 

Since our history file is just one long DataFrame, there could be adjacent songs where I stopped listening and a day later, in a completely different mood, I started listening to something else. If these were included, we would get some garbage edges in our graph so it's best and relatively simple to throw them out.

[API endpoint]: https://developer.spotify.com/documentation/web-api/reference/player/get-recently-played/
[gist]: https://gist.github.com/SamL98/c1200a30cdb19103138308f72de8d198
[sputil gist]: https://gist.github.com/SamL98/ff1448aa1f92bf671a549357449192e5
