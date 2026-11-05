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

import "strings"

// The default extensions that are never pages: styles, scripts, fonts, feeds, applets and images. The list is AWStats'
// default NotPageList: https://github.com/eldy/AWStats/blob/AWSTATS_8_0/wwwroot/cgi-bin/awstats.pl#L1849-L1868
var defaultNotPages = []string{
	"bmp", "class", "css", "eot", "gif", "ico", "jpeg", "jpg", "js", "png", "rss", "swf", "webp", "woff", "woff2",
	"xml",
}

// The extensions of images and downloads: a request for one is never a page. The list is AWStats':
// https://github.com/eldy/AWStats/blob/AWSTATS_8_0/wwwroot/cgi-bin/lib/mime.pm#L63-L72
var fileTypes = setOf(
	"7z", "aac", "ace", "ai", "apk", "asf", "avi", "azw", "azw3", "bin", "bmp", "bz2", "cab", "cdr", "csv", "deb",
	"divx", "dmg", "doc", "docx", "emz", "epub", "f4v", "flac", "flv", "frl", "gif", "gpx", "gz", "heic", "ico", "iso",
	"jar", "jpeg", "jpg", "kml", "kmz", "lit", "log", "lzma", "m3u", "m4a", "m4v", "mdb", "mkv", "mobi", "mov", "mp3",
	"mp4", "mpeg", "mpg", "msi", "mso", "odb", "odf", "odg", "odm", "odp", "ods", "odt", "oga", "ogg", "ogv", "ogx",
	"otg", "oth", "otp", "ots", "ott", "ova", "ovf", "oxt", "pdf", "pkg", "png", "pps", "ppt", "pptx", "psd", "qcow2",
	"qt", "rar", "raw", "rm", "rpt", "rtf", "svg", "svgz", "sxc", "sxd", "sxg", "sxi", "sxm", "sxw", "tar", "tbz2",
	"tgz", "tif", "tiff", "toast", "txt", "vcd", "vdi", "vhdx", "vmdk", "vpc", "wav", "webm", "webp", "wma", "wmf",
	"wmv", "wmz", "xls", "xlsx", "xsl", "xz", "z", "zip",
)

// Reports whether a request path is a page: it has no extension, or one that is neither in notPage nor an image or
// download type.
func isPage(path string, notPage map[string]bool) bool {
	ext := extension(path)

	return ext == "" || !notPage[ext] && !fileTypes[ext]
}

// Returns the extension of a path in lowercase: the 1 to 6 letters, digits or underscores after its last dot. Anything
// else there means the path has none. The rule follows AWStats:
// https://github.com/eldy/AWStats/blob/AWSTATS_8_0/wwwroot/cgi-bin/awstats.pl#L18529
func extension(path string) string {
	dot := strings.LastIndexByte(path, '.')
	if dot < 0 || len(path)-dot-1 > 6 {
		return ""
	}

	for i := dot + 1; i < len(path); i++ {
		if !wordByte(path[i]) {
			return ""
		}
	}

	return strings.ToLower(path[dot+1:])
}

// Reports whether c is an ASCII letter, a digit or an underscore.
func wordByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_'
}

// Returns the set of the given strings in lowercase.
func setOf(items ...string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, s := range items {
		set[strings.ToLower(s)] = true
	}

	return set
}
