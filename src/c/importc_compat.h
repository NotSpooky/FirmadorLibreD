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

/* Ajustes de las cabeceras del sistema para ImportC; cada módulo de src/c lo incluye antes
 * que nada.
 *
 * macOS declara size_t y ptrdiff_t a partir de otro typedef (__darwin_size_t,
 * __darwin_ptrdiff_t). ImportC hace de ellos un alias de un alias, que D toma como un
 * símbolo distinto del size_t y el ptrdiff_t de object aunque el tipo sea el mismo, y un
 * módulo de D que importa entero uno de src/c ya no sabe cuál usar. Aquí se declaran
 * directamente con el tipo del compilador, como hacen Linux y Windows, y las guardas que
 * comparten las cabeceras de macOS y de clang (_SIZE_T, _PTRDIFF_T) evitan que se repitan. */

#ifndef FIRMADOR_IMPORTC_COMPAT_H
#define FIRMADOR_IMPORTC_COMPAT_H

#ifdef __APPLE__
#ifndef _SIZE_T
#define _SIZE_T
typedef __SIZE_TYPE__ size_t;
#endif
#ifndef _PTRDIFF_T
#define _PTRDIFF_T
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#endif
#endif

#endif
