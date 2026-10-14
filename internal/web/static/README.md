# Gömülü arayüz asset'leri

Bu dosyalar binary'ye gömülür; CDN veya harici adres kullanılmaz (ADR 0007). Sürümler sabittir;
güncelleme bilinçli bir değişikliktir.

| Dosya | Sürüm | Lisans | Kaynak | SHA-256 |
|---|---|---|---|---|
| `htmx.min.js` | 2.0.11 | 0BSD | https://unpkg.com/htmx.org@2.0.11/dist/htmx.min.js | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| `editor.js` | CodeMirror view 6.43.13, state 6.7.6, language 6.12.4, commands 6.11.1; @lezer/highlight 1.2.5 | MIT | `tools/editor/build.sh` (esbuild 0.28.2) | `48d1c4ae0cda2bbe3a445cc7d82432caf96a373c2d2bd249e3c370849ae70758` |

- htmx: Zero-Clause BSD (0BSD), Copyright (c) 2020 Big Sky Software.
- CodeMirror 6 ve Lezer: MIT, Copyright (C) 2018-2021 Marijn Haverbeke and others. Kaynak ve sürümler `tools/editor/`.

Projenin kendi dosyaları (dış kaynak değil): `tokens.css`, `components.css`, `ui.js`. Kurallar için
[docs/ui-guide.md](../../../docs/ui-guide.md) dosyasına bakın. Bootstrap kaldırıldı.

İkonlar `internal/web/ui/icons.go` içinde gömülüdür (Iconify üzerinden kopyalandı):
- mdi-light: Open Font License 1.1 (https://github.com/Templarian/MaterialDesignLight)
- mdi (eksik olanlar, `-outline` çeşitleri): Apache 2.0 (https://github.com/Templarian/MaterialDesign)
- svg-spinners (`spinner`): MIT (https://github.com/n3r4zzurr0/svg-spinners)

## Neden htmx 2.0.11 (4.0.0 değil)

htmx 4.0.0 yayımlandı ama htmx ekibi 2.x hattını npm `latest` olarak bırakıyor (4.0 `next`); htmx.org
quick-start hâlâ 2.0.11 gösteriyor. 4.x olay adlarını (`htmx:configRequest` → `htmx:config:request`) ve
attribute kalıtımını kırar; 2-3 kişilik bir admin paneli için riske değmez. Karar 2026-09-30'da
`researcher` ile doğrulandı (F1-015).
