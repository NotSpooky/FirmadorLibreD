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

/* Cabeceras de libsecret para ImportC (sólo Linux); las usa
 * src/firmador/connections/passwordprovider.d para guardar la contraseña del almacén de
 * tokens en el llavero del escritorio. */

/* ImportC no conoce este intrínseco de GCC que usan las funciones en línea de GLib; -1
 * significa «tamaño desconocido», que es lo que GCC responde cuando no puede deducirlo. */
#define __builtin_object_size(pointer, type) ((size_t) -1)

#include "firmador_pkgdefs.h"
#include <libsecret/secret.h>
