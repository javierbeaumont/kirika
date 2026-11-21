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
	"crypto/hmac"
	"crypto/sha256"
)

// The class of a human's visits.
var humanVisits = newClass(false, groupCorrect)

// Returns the ID of a client's session under salt.
func idUnder(salt []byte, host, client string, visitClass class) []byte {
	return sessionID(hmac.New(sha256.New, salt), host, client, visitClass)
}
