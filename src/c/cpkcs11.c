/* Firmador is a program to sign documents using AdES standards.

Copyright (C) Firmador authors.

This file is part of Firmador.

Firmador is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Firmador is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Firmador.  If not, see <http://www.gnu.org/licenses/>.  */

/* Cabecera PKCS#11 para ImportC; la envuelve src/firmador/tokens/pkcs11.d. Se usa la copia
 * de p11-kit incluida en src/c/vendor (su licencia permite redistribuirla) para que la
 * compilación no dependa de que el sistema la tenga instalada. */

#include "firmador_pkgdefs.h"
#include "vendor/pkcs11.h"
