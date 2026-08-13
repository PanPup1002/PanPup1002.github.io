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
  }, {
    name: '椿 (Live)',
    artist: 'Jabo',
    url: '/music/chun.mp3',
    cover: '/music/chun.jpg'
  }, {
    name: 'Love Is Gone (Acoustic)',
    artist: 'SLANDER / Dylan Matthew',
    url: '/music/loveisgone.mp3',
    cover: '/music/loveisgone.jpg'
  }, {
    name: "It's You",
    artist: 'HENRY 刘宪华',
    url: '/music/itsyou.mp3',
    cover: '/music/itsyou.jpg'
  }],
  order: 'list',
  loop: 'all',
  preload: 'auto',
  listFolded: false
});
</script>
