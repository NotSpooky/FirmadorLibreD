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

/*
 * Puente con mupdf. mupdf señala los errores con setjmp/longjmp (fz_try/fz_catch), que
 * ImportC no puede compilar con garantías, así que este archivo lo compila el compilador
 * de C del sistema (tools/prebuild.sh) y el código D llama a mupdf siempre dentro de
 * fl_try: un error de mupdf salta de vuelta aquí y se convierte en un código y un mensaje.
 *
 * Las funciones que se pasan a fl_try son D nothrow sin destructores pendientes ni
 * cerrojos tomados: un longjmp las abandona sin ejecutar nada más (ver
 * src/firmador/pdf/engine.d).
 */

#include <stdio.h>
#include <string.h>
#include <mupdf/fitz.h>
#include "mupdfshim.h"

fz_context *fl_new_context(char *error, size_t errorLength)
{
	fz_context *ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	if (ctx == NULL) {
		snprintf(error, errorLength, "%s", "mupdf no pudo crear su contexto");
		return NULL;
	}
	fz_try(ctx)
		fz_register_document_handlers(ctx);
	fz_catch(ctx) {
		snprintf(error, errorLength, "%s", fz_caught_message(ctx));
		fz_ignore_error(ctx);
		fz_drop_context(ctx);
		return NULL;
	}
	return ctx;
}

void fl_drop_context(fz_context *ctx)
{
	fz_drop_context(ctx);
}

int fl_try(fz_context *ctx, fl_callback callback, void *argument, char *error, size_t errorLength)
{
	/* volatile: se modifica después de setjmp y se lee tras el longjmp. */
	volatile int code = 0;
	if (errorLength > 0)
		error[0] = '\0';
	fz_try(ctx)
		callback(ctx, argument);
	fz_catch(ctx) {
		code = fz_caught(ctx);
		if (code == 0)
			code = FZ_ERROR_GENERIC;
		snprintf(error, errorLength, "%s", fz_caught_message(ctx));
		fz_ignore_error(ctx);
	}
	return code;
}

void fl_throw(fz_context *ctx, const char *message)
{
	fz_throw(ctx, FZ_ERROR_ARGUMENT, "%s", message);
}
