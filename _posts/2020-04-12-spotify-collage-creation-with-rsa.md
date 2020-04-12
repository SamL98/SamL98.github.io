---
layout: post
title:  "Creating Spotify Album Art Collages with PCA"
date:   2020-04-10 18:12:10 -0500
categories: jekyll update
---

In this post, I'll be explaining how I created this collage of album art:

![collage](/images/collage.png)

## Getting the Album Art

As you might expect, I used the Spotify API to download the album art. I won't go through the code for this but if you know how to interact with an API, it's super straightforward. For this collage, I chose to use the album covers for the 100 songs in my "Top Songs of 2019" + the 100 songs I most recently added to my library.

## Decomposing the Image Set

Now we'll want to perform PCA on all of the flattened images. For those who don't know, PCA is a method of projecting a dataset onto its "principal components". Here, principal components are defined as the axes in which the data varies the most. If we then choose to represent the data only using some of these principal components, then we have a more compact representation of how the data varies to use for comparing how similar two vectors in the space are. Here's a link to the [Wikipedia](https://en.wikipedia.org/wiki/Principal_component_analysis) if you want to learn the math behind it.

In our case, each vector in the space is an image. Therefore, when performing PCA, we will first be analyzing which pixels change the most across all the images. Then we will be using these pixels as a smaller vector representation of the image to use for fast comparison. This is a fairly naive approach since images change rapidly on a per-pixel basis. However, looking at the collage produced, it seems to work well enough (you can be the judge of that!). I would suspect that since many album covers (at least the ones in my library) are composed of a central object surrounded by a solid color, picking pixels from the background captures the varying color across images.

## The Code

Without further ado, let's go over the code for this.

First, we'll load all of the images into a 2D array:

```python
import os
from os.path import join
import numpy as np
from skimage.io import imread
from skimage.transform import resize

TILE_SIZE = 128
IMAGE_DIR = 'images'

tiles = []

for i, f in enumerate(os.listdir(IMAGE_DIR)):
    tile = imread(join(img_dir, f))
    tile = (255 * imresize(tile, (TILE_SIZE, TILE_SIZE))).astype(np.uint8).ravel()
    tiles.append(tile)

tiles = np.array(tiles)
```
