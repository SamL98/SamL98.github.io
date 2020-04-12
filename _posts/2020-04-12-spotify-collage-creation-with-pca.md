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

for fname in os.listdir(IMAGE_DIR):
    tile = imread(join(img_dir, fname))
    tile = imresize(tile, (TILE_SIZE, TILE_SIZE)) # resize all the images to a uniform size
    tile = (255 * tile).astype(np.uint8).ravel()  # convert the image type back to bytes and flatten it
    tiles.append(tile)

tiles = np.array(tiles)
```

Now, we'll perform PCA on the dataset. For the collage at the beginning of the article, I used 10 components:

```python
from sklearn.decomposition import PCA

NUM_COMP = 10
pca = PCA(NUM_COMP)

tiles_pca = pca.fit_transform(tiles)
pairwise_similarity = tiles_pca.dot(tiles_pca.T)

# Ignore self-similarity
n_tiles = len(tiles)
pairwise_similarity[np.arange(n_tiles), np.arange(n_tiles)] = 0
```

Here, we're using a nice vectorized trick to compute the pairwise similarity. `tiles_pca` will have shape `(n_tiles, NUM_COMP)` where each row is the PCA-projected vector for each image. Therefore, `tiles_pca` will have shape `(NUM_COMP, n_tiles)` and each column will have the vector for each image.

If we then multiply these two matrices together, each element in the result will be computed as:
```
(im1_comp1 im1_comp2 ... im1_comp10) * (im2_comp1    = (im1_comp1 * im2_comp1 + im1_comp2 * im2_comp2 + ... + im1_comp10 * im2_comp10)
                                        im2_comp2
                                        ...
                                        img2_comp10)
```
or the dot product between each image vector. This is equivalent to the unnormalized cosine similarity. So the metric will be biased towards image vector pairs with a large magnitude. Therefire, this metric should make the math nerds cringe but we don't care because it's functionally OK.

As a final step, we zero out the diagonal of the `pairwise_similarity` matrix. This is because the diagonal corresponds to the similarity between an image and itself. This will obviously be the highest of all similarities for this image, so we want to ignore it as to not make our collage look blocky.

## Arranging the Tiles

Now that we have a pseudo-pairwise similarity between each tile, we need to use this to construct a collage with a nice color gradient.
