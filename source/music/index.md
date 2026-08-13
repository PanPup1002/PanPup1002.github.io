---
title: Music
date: 2026-08-13 10:00:00
description: Music player
---

<link rel="stylesheet" href="/css/APlayer.min.css">

<div id="aplayer"></div>

<script src="/js/APlayer.min.js"></script>
<script>
const ap = new APlayer({
  container: document.getElementById('aplayer'),
  audio: [{
    name: 'Fractures',
    artist: 'HHYB',
    url: '/music/fractures.mp3',
    cover: '/music/fractures.jpg'
  }],
  order: 'list',
  loop: 'all',
  preload: 'auto',
  listFolded: false
});
</script>
