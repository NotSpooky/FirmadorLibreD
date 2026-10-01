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

/* Cabeceras de mupdf y del puente src/shim/mupdfshim.c para ImportC; las envuelve
 * src/firmador/pdf/engine.d. */

#include "importc_compat.h"
#include "firmador_pkgdefs.h"

/* mupdf/fitz/system.h deja inline como palabra clave sólo si está definido
 * __STDC_VERSION_ (así, con un guion bajo de menos); si no, con MSVC o GCC hace
 * #define inline __inline. Con el #define __inline inline de importc.h los dos se anulan
 * y el __inline de las cabeceras que siguen (corecrt_math.h en Windows) llega sin
 * cambiar a ImportC, que no lo entiende. Compilamos en C11: la rama de C99 es la que
 * corresponde. Si mupdf corrige el nombre, esto deja de hacer falta sin estorbar. */
#define __STDC_VERSION_ __STDC_VERSION__

#include <mupdf/fitz.h>
#include <mupdf/pdf.h>
#include "../shim/mupdfshim.h"
