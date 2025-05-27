BEGIN {
  srand(seed)

  charset = ""
  # Space (ASCII 32)
  charset = charset sprintf("%c", 32)
  # Digits 0-9 (ASCII 48-57)
  for (c = 48; c <= 57; c++) { charset = charset sprintf("%c", c) }
  # Uppercase letters A-Z (ASCII 65-90)
  for (c = 65; c <= 90; c++) { charset = charset sprintf("%c", c) }
  # Lowercase letters a-z (ASCII 97-122)
  for (c = 97; c <= 122; c++) { charset = charset sprintf("%c", c) }
  # Punctuation (ASCII 33-47, 58-64, 91-96, 123-126)
  for (c = 33; c <= 47; c++) { charset = charset sprintf("%c", c) }
  for (c = 58; c <= 64; c++) { charset = charset sprintf("%c", c) }
  for (c = 91; c <= 96; c++) { charset = charset sprintf("%c", c) }
  for (c = 123; c <= 126; c++) { charset = charset sprintf("%c", c) }

  clen = length(charset)

  # Generate unique lines
  for (u = 1; u <= nuniqlines;) {
    len = minlen + int(rand() * (maxlen - minlen + 1))
    line = ""
    for (j = 1; j <= len; j++) {
      idx = 1 + int(rand() * clen)
      line = line substr(charset, idx, 1)
    }
    if (uniqlines[line] == 0) {
      uniqlines[line]++
      lines[u++] = line
    }
  }

  # Output nlines lines, randomly chosen from the unique set
  while (nlines > 0) {
    pick = 1 + int(rand() * nuniqlines)
    print lines[pick]
    nlines--
  }
}
