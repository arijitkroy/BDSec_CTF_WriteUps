# Coordination Password - BDSEC CTF Writeup

## Challenge

**Name:** Coordination Password

**Category:** OSINT / Steganography / Cryptography

### Description

> We have found that pmsiam0 has friends who do not have any security
> knowledge; therefore, they leaked their notes. Can you unlock this
> image with the password so that your task will be completed?

Flag format:

`BDSEC{Partialflag_password}`

The password must be lowercase.

------------------------------------------------------------------------

# Initial Files

``` text
unlock.zip
└── unlock.jpg
```

The ZIP archive itself was not password protected.

------------------------------------------------------------------------

# Step 1 -- Inspect the ZIP

``` bash
zipinfo -v unlock.zip
```

The archive contained:

-   One file: `unlock.jpg`
-   No ZIP comment
-   No file comment
-   Standard Deflate compression

This indicated there were no metadata hints.

------------------------------------------------------------------------

# Step 2 -- Inspect the Image

Useful commands:

``` bash
file unlock.jpg
exiftool unlock.jpg
strings unlock.jpg
binwalk unlock.jpg
```

Observations:

-   No useful EXIF metadata
-   No embedded archive
-   No appended payload
-   No readable password

The challenge description instead hinted at leaked notes.

------------------------------------------------------------------------

# Step 3 -- Finding the friend of psiam0

Flow:
- Went to psiam0's Github
- Visited their latest created repository named 'myfirsttestwebsite'
- Looked for contributors and found their friend named siamsec404.
- Visited their repository to find "Personal-notes" with two files namely `Notes.md` and `partialone.zip`

------------------------------------------------------------------------

# Step 3 -- Recover the Leaked Notes from `Notes.md`

The leaked note contained a short story and coordinate list.

Story:

``` text
The dark sky above the castle was heavy with storm clouds.
A brave king stood watching the violent wind.
Guards kept their silent watch near the steep towers.
```

Coordinates:

``` text
1-2-4  2-3-3  1-9-2  2-3-4  1-1-2  1-1-1
2-8-3  1-1-3  2-2-4  1-4-5  1-2-3  1-3-1
1-11-2  1-5-3  1-6-6  3-2-3  3-8-1
```

------------------------------------------------------------------------

# Step 4 -- Decode the Coordinates

Coordinates follow the format:

`Line – Word – Letter`

Example:

`1-2-4`

-   Line 1
-   Word 2 = dark
-   Letter 4 = **K**

Decoding every coordinate gives:

`KNIGHT NEVER SLEEPS`

The required lowercase password is:

``` text
knightneversleeps
```

------------------------------------------------------------------------

# Step 5 -- Extract Hidden Data

Check whether data is embedded:

``` bash
steghide info unlock.jpg
```

Extract it:

``` bash
steghide extract -sf unlock.jpg -p knightneversleeps
```

A hidden `secrets.txt` is extracted that contains:
``` text
BDSEC{partialflag1_knightneversleeps}
```

------------------------------------------------------------------------

# Step 6 -- Analyze the Extracted QR from `partialone.zip`

Crop the two QR halves.

Align and merge them into one complete QR code.

Scan the reconstructed QR to obtain the **partial flag**.

------------------------------------------------------------------------

# Step 8 -- Construct the Flag

``` text
BDSEC{Kn1ghT404_Y0U_are_Hack3r_knightneversleeps}
```

------------------------------------------------------------------------

# Tools Used

-   zipinfo
-   file
-   exiftool
-   strings
-   binwalk
-   steghide
-   ImageMagick / GIMP
-   QR scanner