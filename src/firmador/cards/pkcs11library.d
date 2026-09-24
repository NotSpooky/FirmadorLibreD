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

/**
 * Qué biblioteca PKCS#11 se usa (CRSigner.getPkcs11Lib): la de la variable LIBASEP11, la
 * que se configuró a mano, la del controlador JCOP4 si está instalado, o la de Athena en
 * su ruta de cada sistema.
 */
module firmador.cards.pkcs11library;

import std.file : exists, isFile;
import std.path : buildPath;
import std.process : environment;

import firmador.configuration : athenaPkcs11Library, jcop4Pkcs11Library, pkcs11LibraryEnvironmentVariable;

/// Candidatos en orden de preferencia (función pura para poder probar la precedencia).
string choosePkcs11Library(string environmentValue, string configuredLibrary, string jcop4Library,
    string defaultLibrary) pure nothrow @safe {
  if (environmentValue.length) return environmentValue;
  if (configuredLibrary.length) return configuredLibrary;
  if (jcop4Library.length) return jcop4Library;
  return defaultLibrary;
}

/// Biblioteca PKCS#11 que corresponde a esta máquina y a la configuración.
string pkcs11LibraryPath(string configuredLibrary) @trusted {
  version (Windows) {
    string jcop4 = buildPath(environment.get("PROGRAMFILES", `C:\Program Files`), jcop4Pkcs11Library);
    string athena = buildPath(environment.get("SystemRoot", `C:\Windows`), athenaPkcs11Library);
  } else {
    string jcop4 = jcop4Pkcs11Library;
    string athena = athenaPkcs11Library;
  }
  string installedJcop4 = exists(jcop4) && isFile(jcop4) ? jcop4 : null;
  return choosePkcs11Library(environment.get(pkcs11LibraryEnvironmentVariable), configuredLibrary, installedJcop4,
    athena);
}

@("should prefer the environment, then the settings, then JCOP4 and last Athena when choosing the library")
unittest {
  assert(choosePkcs11Library("/env.so", "/conf.so", "/jcop4.so", "/athena.so") == "/env.so");
  assert(choosePkcs11Library(null, "/conf.so", "/jcop4.so", "/athena.so") == "/conf.so");
  assert(choosePkcs11Library("", "", "/jcop4.so", "/athena.so") == "/jcop4.so");
  assert(choosePkcs11Library(null, null, null, "/athena.so") == "/athena.so");
}
