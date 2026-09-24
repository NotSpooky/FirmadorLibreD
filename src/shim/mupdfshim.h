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

/* Interfaz del puente con mupdf (mupdfshim.c). La incluyen tanto el compilador de C
 * como ImportC (src/c/cmupdf.c). */

#ifndef FIRMADOR_MUPDFSHIM_H
#define FIRMADOR_MUPDFSHIM_H

#include <stddef.h>
#include <mupdf/fitz.h>

typedef void (*fl_callback)(fz_context *ctx, void *argument);

/* Crea un contexto con los manejadores de documentos registrados; NULL y el motivo en
 * error si falla. */
fz_context *fl_new_context(char *error, size_t errorLength);

void fl_drop_context(fz_context *ctx);

/* Ejecuta callback dentro de fz_try. Devuelve 0 si terminó bien, o el código de error de
 * mupdf con su mensaje en error. */
int fl_try(fz_context *ctx, fl_callback callback, void *argument, char *error, size_t errorLength);

/* Lanza un error de mupdf desde un callback de fl_try, para abandonarlo por el mismo
 * camino que los errores de la propia biblioteca. */
void fl_throw(fz_context *ctx, const char *message);

#endif
