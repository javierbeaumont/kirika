// kirika: private analytics from HTTP access logs
//
// Copyright (C) 2026 Javier Beaumont <javierbeaumont@users.noreply.github.com>
//
// This file is part of kirika.
//
// kirika is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// kirika is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with kirika. If not, see <https://www.gnu.org/licenses/>.

package kvstore

import (
	"maps"
	"net/url"
	"strings"
	"unicode"
)

// The default file names of an index page. The list is the DefaultFile of AWStats' sample configuration:
// https://github.com/eldy/AWStats/blob/AWSTATS_8_0/wwwroot/cgi-bin/awstats.model.conf#L465-L470
var defaultIndexPages = []string{"index.html", "index.php"}

// The extensions of files: AWStats' file types and the files it leaves untyped, plus current formats and what scanners
// probe for. AWStats' are in: https://github.com/eldy/AWStats/blob/AWSTATS_8_0/wwwroot/cgi-bin/awstats.pl#L1849-L1868
// https://github.com/eldy/AWStats/blob/AWSTATS_8_0/wwwroot/cgi-bin/lib/mime.pm#L74-L266
var fileTypes = setOf(
	"7z", "aac", "ace", "ai", "apk", "appimage", "asc", "asf", "atom", "avi", "avif", "azw", "azw3", "bak", "bin",
	"bmp", "bz2", "cab", "cdr", "cf", "class", "conf", "css", "csv", "deb", "divx", "dll", "dmg", "doc", "docx", "dtd",
	"emz", "env", "eot", "epub", "exe", "f4v", "flac", "flatpak", "flatpakref", "flv", "fon", "frl", "gif", "gpg",
	"gpx", "gz", "heic", "htaccess", "htpasswd", "ico", "img", "ini", "iso", "jar", "jnlp", "jpeg", "jpg", "js", "json",
	"kml", "kmz", "lit", "log", "lzma", "m3u", "m3u8", "m4a", "m4v", "map", "md5", "mdb", "mjs", "mkv", "mobi", "mov",
	"mp3", "mp4", "mpeg", "mpg", "msi", "mso", "odb", "odf", "odg", "odm", "odp", "ods", "odt", "oga", "ogg", "ogv",
	"ogx", "otf", "otg", "oth", "otp", "ots", "ott", "ova", "ovf", "oxt", "pdf", "pgp", "pkg", "png", "pps", "ppt",
	"pptx", "psd", "qcow2", "qt", "rar", "raw", "rm", "rpm", "rpt", "rss", "rtf", "sha1", "sha256", "sha512", "sig",
	"snap", "sql", "svg", "svgz", "swf", "sxc", "sxd", "sxg", "sxi", "sxm", "sxw", "tar", "tbz2", "tgz", "tif", "tiff",
	"toast", "torrent", "ts", "ttf", "txt", "vcd", "vdi", "vhdx", "vmdk", "vpc", "wasm", "wav", "webm", "webmanifest",
	"webp", "wma", "wmf", "wmv", "wmz", "woff", "woff2", "xls", "xlsx", "xml", "xsl", "xz", "yaml", "yml", "z", "zip",
	"zst",
)

// Returns the extensions that are never pages: the file types and notPages, without pages.
func notPageSet(notPages, pages []string) map[string]bool {
	set := maps.Clone(fileTypes)
	maps.Copy(set, setOf(notPages...))

	for entry := range setOf(pages...) {
		delete(set, entry)
	}

	return set
}

// Reports whether a request path is a page: it has no extension, or one not in notPage.
func isPage(path string, notPage map[string]bool) bool {
	ext := extension(path)

	return ext == "" || !notPage[ext]
}

// Returns path cut to its directory when it ends in one of suffixes, "/" and an index page name each.
func fold(path string, suffixes []string) string {
	for _, s := range suffixes {
		if strings.HasSuffix(path, s) {
			return path[:len(path)-len(s)+1]
		}
	}

	return path
}

// Returns value up to the first of chars, or whole without any.
func cutAt(value, chars string) string {
	if i := strings.IndexAny(value, chars); i >= 0 {
		return value[:i]
	}

	return value
}

// Returns the extension of a path in lowercase: the word characters of any script after its last dot, once that text's
// escapes are decoded. Anything else there, such as a byte that is not UTF-8 or a malformed escape, means the path has
// none.
func extension(path string) string {
	dot := strings.LastIndexByte(path, '.')
	if dot < 0 {
		return ""
	}

	ext, err := url.PathUnescape(path[dot+1:])
	if err != nil {
		return ""
	}

	for _, char := range ext {
		if !wordRune(char) {
			return ""
		}
	}

	return strings.ToLower(ext)
}

// Reports whether char is a word character, as Perl's \w defines it for Unicode.
func wordRune(char rune) bool {
	return unicode.In(char, unicode.Letter, unicode.Mark, unicode.Digit, unicode.Nl, unicode.Pc,
		unicode.Other_Alphabetic, unicode.Join_Control)
}

// Returns the set of the given strings in lowercase.
func setOf(items ...string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, s := range items {
		set[strings.ToLower(s)] = true
	}

	return set
}
