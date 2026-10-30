# ZBTC: investigación, límites y evidencia

> Registro de investigación del PoC. Afirmaciones verificadas en la fuente: **[V]**.
> Inferencias propias: **[I]**. Resultados del PoC ejecutado: **[T: id]**, donde `id` es el
> test que lo demuestra. Todo lo que no lleva marca es contexto.

## 1. Conclusión

**Qué está construido y probado.** Una implementación propia y mínima de la capa de
transferencias internas del paper *Shielded Bitcoin* sobre Bitcoin Core 32.1 en regtest:
- notas privadas con **unidades simuladas**;
- un sobre de 572 bytes en un solo `OP_RETURN` por transferencia;
- una prueba Groth16 (Circom + snarkjs) que verifica cada cliente;
- replay determinista en el orden que fija Bitcoin, donde el primer nullifier gana.

Alice→Bob→Carol funciona de punta a punta, y dos procesos independientes calculan el mismo
estado (digest idéntico) [T: demo, happy-path, agreement].

**Qué demuestra exactamente.** El caso **B** de la §5: valor privado anclado y ordenado por
Bitcoin, con validación del lado del cliente, sin otra blockchain y sin bridge.

**Qué NO demuestra.** No es BTC privado nativo (caso **C**).
- Las unidades no tienen respaldo en BTC y no se pueden redimir.
- Bitcoin no hace cumplir ninguna regla del protocolo. Solo ordena y almacena los sobres.
- La validez la deciden los clientes, y quien no corre el indexer no está protegido.

**Por qué el caso C no se puede construir hoy.** Ninguna pieza existente permite, sin sumar
un supuesto de confianza nuevo, que un UTXO de BTC solo se pueda gastar si el estado
shielded lo autoriza:
- **PIPEs v2** libera la clave una sola vez y no restringe los gastos posteriores.
- **AADP** existe solo como estimación de costos.
- **BitVM2** necesita que al menos 1 de n firmantes sea honesto, y además operadores con
  liquidez.

Ver §9.

## 2. Cómo se relacionan los papers

| Trabajo | Qué es | Estado real |
|---|---|---|
| **PIPEs v2** (Abdalla et al., alloc init; ePrint 2026/186) | Cifra con witness encryption (WE) una clave secreta Schnorr `sk`. Cualquiera que tenga un testigo del enunciado `x` puede descifrarla. | Construcción teórica. El WE que usa es AADP. |
| **AADP** (ePrint 2026/175) | Candidato de WE basado en *affine determinant programs* aritméticos. | No hay implementación, solo un script de modelado de costos. |
| **Shielded Bitcoin** (Shikhelman, Komarov, Moskvin; sep. 2026) | Capa de notas al estilo Sapling: sobres `OP_RETURN`, Groth16 y replay por indexers. | Especificación completa de la capa interna, sin entrada ni salida de BTC. |
| **Shielded CSV** (Nick, Eagen, Linus; ePrint 2025/068) | Validación del lado del cliente con PCD recursivo y nullifiers firmados de unos 64 B. | Teórico. El repo es pseudocódigo con primitivas `unimplemented!()`. |

**PIPEs v2**
- Lo que se cifra con WE es la clave misma, `ct ← WE.Enc(x, sk)` (§4, p.12), no una firma.
  El enunciado es típicamente "existe una prueba SNARK válida" (§5.3, p.16) [V].
- La propiedad que llaman "covenant" es un solo bit, desbloquear o no (Def. 1.1, p.3) [V].

**AADP**
- "We do not have a full implementation and only a modeling script" (§4.10, p.35) [V].
- El ciphertext estimado es de unos 338 TiB (PIPEs §5.3.1, p.17).
- La seguridad es heurística, sin reducción a supuestos falsables (PIPEs §5, p.14; AADP
  §3.5, p.16) [V].
- El ataque de linearización figura como "inconclusive… further research is required"
  (AADP §3.4, p.16) [V].
- El repo `alloc-init/crypto-research-aadp-estimates` tiene tres archivos: `main.py` (un
  modelo de costos) y dos scripts Sage. No tiene tests ni CI [V].
- Recalculado con su propio modelo, descifrar lleva unas 2.042 horas-núcleo [V/I].

**Shielded Bitcoin**
- Entrada y salida de BTC están fuera de alcance (resumen; §1.2, p.4; §20.4, p.35;
  §22.3, p.39) [V].
- La génesis es un "inventario declarado por el despliegue" (p.3) [V].
- El paper no menciona witness encryption. A PIPEs solo lo cita como dirección futura [V].

**Shielded CSV**
- Maneja un único activo. Usar BTC requiere un bridge (sugiere BitVM), un *one-way peg* o
  *swaps* PTLC (A.1.2–A.1.3, p.29) [V].
- La comparación desde el otro lado: Shielded Bitcoin dice que SCSV necesita un bridge y que
  perder el estado local es irrecuperable (§2, p.5) [V].

**Conclusión [I].** Estos trabajos no forman juntos una implementación completa. Son
piezas: una capa shielded especificada (SB), un mecanismo teórico de desbloqueo (PIPEs) y un
candidato de WE que todavía no existe (AADP).

## 3. Distinciones que importan

### 3.1 Witness encryption frente a un servidor que verifica y firma

| | PIPE (WE) | Servidor u oráculo que verifica y firma |
|---|---|---|
| Cuándo se confía | Una sola vez, en el Setup: quien generó `sk` pudo quedársela (PIPEs, Remark p.12; el modelo asume un Setup honesto, Fig. 2, p.11) | En cada gasto: el servidor puede robar, filtrar o negarse |
| Qué recibe quien gana | La clave `sk` completa | Una firma sobre una transacción concreta |
| Ligadura con la transacción | Ninguna | Sí, el servidor firma solo la tx que validó |
| Estado | Teórico (AADP no implementado) | Trivial de implementar, pero es un custodio o una federación |

El paper PIPEs v2 no hace esta comparación [V]. Mirando las dos columnas [I]: un servidor
con FROST t-de-n que firma la transacción exacta liga mejor el gasto que PIPE, pero es una
federación, y el usuario excluyó federaciones en este experimento.

### 3.2 Liberar una clave no es un covenant persistente

- Una vez liberada `sk`, el poseedor "can generate Schnorr signatures on arbitrary messages"
  (§1.1, p.3) [V].
- PIPEs "does not emulate covenant mechanisms requiring persistent… checks or opcode-level
  transaction binding (such as OP_CTV)" (p.3) [V].
- Consecuencias [I]:
  - quien descifra decide libremente a dónde van los fondos;
  - si varias personas tienen un testigo, compiten por gastar el UTXO;
  - cualquier otro UTXO enviado a la misma `pk` queda igual de expuesto.

### 3.3 Hash, prueba ZK y firma Schnorr no cumplen la misma función

En ZBTC la autorización la da la prueba, sin firma:
- `owner = Poseidon(1, sk_spend)` forma parte del `cm` de cada entrada.
- `sk_nf = Poseidon(2, sk_spend)` se deriva dentro del circuito.

Por eso, para generar la prueba hay que conocer `sk_spend` [T: C7]. La prueba queda atada a
esta transferencia por sus entradas públicas `[root, h_body, nf0, nf1, cm0, cm1]`; cambiar
cualquier byte del sobre invalida la verificación [T: soundness-d].

Hay un límite: Groth16 es re-aleatorizable. Sí cumple la variante débil de *simulation
extractability*: permite re-aleatorizar una prueba, pero no moverla a otro enunciado
(Baghery, Kohlweiss, Siim, Volkhov, FC 2021, ePrint 2020/811) [V].

Una firma haría falta en tres casos [I]:
- (a) prueba delegada o hardware wallets, donde quien prueba no debe conocer `sk_spend`;
- (b) propiedad con umbral (FROST);
- (c) atar la transferencia a datos que no cubre `h_body`, como quién paga la fee.

**Shielded CSV usa otro mecanismo.** Ahí el nullifier es una firma *sign-to-contract*
sobre el hash de la transacción (§4.1, p.17) [V]. La dirección del *publisher* no está
firmada, así que copiarla solo roba la fee de publicación, por diseño (p.19) [V/I].

### 3.4 Control del UTXO y recuperación

- **En ZBTC no hay UTXO de valor.** El único BTC involucrado es el de las fees, que paga una
  wallet bitcoind normal por actor.
- **El caso C requiere un recorrido concreto que hoy no existe completo:**

  | Paso | PIPE (teórico) | BitVM2 (investigación) |
  |---|---|---|
  | outpoint | depósito a P2TR con key path `pk_PIPE`. El paper dice "P2PKH o P2TR" (§1.4, pp.6–7), pero P2PKH es ECDSA [V/I] | depósito a un script n-de-n con grafo de txs prefirmadas |
  | quién firma | quien descifra `sk` y quien hizo el Setup [I] | el comité n-de-n prefirma; el operador ejecuta |
  | gastos alternativos | el paper no especifica timelocks ni refunds [V]; habría que agregar un script path con CSV [I] | caminos de disputa y *disprove* |
  | si desaparecen los participantes | no hace falta nadie para descifrar, pero el Setup pudo guardar `sk` [I] | se necesita 1 firmante honesto (seguridad) y 1 operador honesto (liveness) |

## 4. Las preguntas de la hipótesis de PoC, respondidas contra ZBTC

1. **Emisión e inflación.**
   - La génesis es `genesis.json`: notas en claro `(v, owner, rseed)`, y cualquiera puede
     verificar que Σv = `totalSupply` [T: indexer-unit genesis].
   - Después, el valor solo se conserva: hay rangos de 64 bits en cada valor y `Σin = Σout`
     dentro del circuito [T: C2, C6].
   - Sin rangos, la conservación módulo p deja inflar: la variante `norange` acepta
     `out = [20, p−10]` contra `in = 10` [T: C3].
   - Si una prueba de esa variante se publica on-chain, el indexer la rechaza [T: soundness-b].
2. **Cómo sabe Bob que la historia es válida.**
   - Bob no recibe historia. Su propio indexer verificó cada prueba desde la génesis, con
     datos que están todos on-chain.
   - Que una nota esté en el árbol bajo una raíz `R[h]` aceptada implica que toda su
     historia fue validada [I].
3. **¿Alcanza con membership?**
   - Sí, pero solo porque hay replay global: el árbol contiene únicamente hojas aceptadas.
   - Sin replay global, membership no alcanza y hace falta recursión o PCD, como en Shielded
     CSV.
   - El costo de no usar recursión es que cada cliente verifica toda la cadena, O(cadena).
     Medido: unos 10 ms por transferencia y unos 1,3 ms por bloque (§8).
4. **Spending key y propietario.** `owner = H(sk_spend)` dentro del commitment de entrada;
   con otra clave la prueba no se puede generar [T: C7].
5. **Autenticación del nullifier y vínculo con los outputs.**
   - `nf = Poseidon(4, sk_nf, rseed, pos)`, con `sk_nf` derivado en el circuito y `pos`
     acotado a 20 bits [T: C4, C12].
   - `nf`, `cm` y `h_body` son entradas públicas de la misma prueba, que así cubre `epk`,
     `ct` y el anchor.
   - Esto sigue la regla del paper (§9, p.15) [V].
6. **Copiar un nullifier de la mempool.**
   - Republicarlo con otros outputs exige una prueba nueva, y eso requiere `sk_spend`; el
     intento da `E_PROOF` [T: soundness-e].
   - Re-aleatorizar la misma prueba solo permite republicar el mismo cuerpo: si esa copia
     entra primero, el efecto es idéntico para Bob [T: soundness-f].
   - Bitcoin ordena; el cliente acepta el primer nullifier y rechaza el sobre posterior
     entero (SB §15, p.23; A.7) [V] [T: double-spend].
7. **Publicaciones inválidas o datos faltantes.**
   - Un sobre inválido se rechaza completo, con un código, y nunca se aplica en parte
     [T: indexer-unit].
   - Como los datos están on-chain, no pueden faltar pruebas.
   - Lo que sí puede pasar en ZBTC es un ciphertext ilegible. El sobre se **acepta** y el
     receptor pierde la nota, porque el cifrado no se prueba en el circuito [T: soundness-g].
     Shielded Bitcoin sí lo prueba (§9, p.15; bloque 5, p.46) [V].
8. **Cómo coinciden dos clientes.**
   - El replay usa solo datos del bloque: altura, hash, orden de transacciones, txid y
     scripts.
   - El estado se resume en un digest que cubre el árbol, los nullifiers, las raíces por
     bloque, la historia aceptada y el perfil (vkey, génesis, W, K, DEPTH)
     [T: agreement, demo].
   - Límite: los "dos clientes" comparten código. Una independencia real exige una segunda
     implementación [I].
9. **Reorgs y recuperación.**
   - **Reorg:** rollback bloque a bloque con registros de deshacer, y nuevo replay.
   - **Anchor que cambió de raíz:** la wallet reconstruye la transferencia. Una
     reconstrucción no permite doble gasto: con la misma `pos` sale el mismo `nf`, y con otra
     `pos` la prueba vieja falla [T: reorg].
   - **Recuperación:** semilla + replay devuelve las notas recibidas, el cambio y el estado
     de gasto, pero no el detalle de los pagos salientes (omitimos `ct_out`) ni los locks
     locales [T: recovery].

**Ciclo de vida de una nota** (SB §10, p.16; §15–16, pp.23–24) [V]:
- **`candidate`**: la nota se ve en la mempool. El receptor descifra, recomputa `cm` y
  valida el sobre contra `tip+1`. Nunca se suma al saldo.
- **`confirmed(k)`**: el replay la aceptó y asignó `pos`.
- **`spendable`**: hay un testigo bajo un anchor permitido y `k ≥ K`.
- **`spent`**: el `nf` de la nota fue aceptado en la cadena activa. **La mempool nunca es
  estado.**

## 5. Qué significa "Bitcoin privado": la taxonomía A/B/C

| | A. Privacidad de recepción (Silent Payments) | B. Notas privadas ancladas en Bitcoin (este PoC) | C. BTC nativo controlado y recuperable mediante notas |
|---|---|---|---|
| Qué se oculta | que dos pagos vayan a la misma dirección estática | montos, emisor, receptor y el grafo entre notas | lo de B, pero sobre BTC real |
| Frente a quién | observadores de la cadena | todos los que no tienen las claves de la nota | todos |
| Qué sigue visible | montos, inputs, grafo de transacciones, claves de input del emisor | cuántas transferencias hay y cuándo; los inputs que pagan fees, que **vinculan las publicaciones**; los montos y dueños de la génesis | depósitos y retiros visibles en el borde |
| Datos off-chain | ninguno | ninguno: todo va en el sobre | depende del diseño |
| Estado hoy | BIP-352 completo; no soportado en Core 32.1 | **funciona en regtest** | requiere WE práctico, BitVM o una federación |

Con 1–3 hojas, el conjunto de anonimato en regtest es trivial (SB p.37). El PoC demuestra
el **mecanismo**, no privacidad práctica [I].

## 6. Circom, BitVM y Silent Payments

- **Circom/snarkjs** *definen* el enunciado y lo *verifican localmente* en cada cliente.
  Bitcoin Script no puede verificar Groth16, porque no hay un opcode para eso. En ZBTC,
  Bitcoin nunca hace cumplir las reglas. Para el caso B, alcanza [T: todo el suite].
- **BitVM2** *hace cumplir* condiciones al gastar BTC de forma optimista:
  - un verificador Groth16 escrito en Script, partido en trozos;
  - transacciones de disputa y *disprove*.

  Sus supuestos: al menos 1 de n firmantes del setup es honesto, y existe un operador honesto
  que adelanta la liquidez de los retiros. El README del repo dice "DO NOT USE IN
  PRODUCTION". No es verificación nativa directa. Agregarlo al MVP no aporta nada a la
  propiedad del caso B.
- **Silent Payments (BIP-352)** es el experimento más simple *con BTC real*, pero solo da
  privacidad de tipo A: no oculta montos ni el grafo, y no tiene nullifiers ni pool. Se
  puede combinar con B (por ejemplo, para las fees), pero no reemplaza un pool shielded.

## 7. Consenso frente a política

- El consenso **no** limita el tamaño ni la cantidad de `OP_RETURN`. Los límites son
  **política de relay y minería**.
- Desde v30, `-datacarriersize` vale 100.000 por defecto y se permiten varios `OP_RETURN`.
- Nuestra tx de 709 vB es estándar con `-acceptnonstdtxn=0`, y un nodo con
  `-datacarriersize=83` la rechaza con `datacarrier` [T: publish].
- Que funcione en regtest **no** demuestra que se propague en mainnet: depende de la
  política de cada nodo y minero.
- En Core 32.1, `createrawtransaction` acepta un solo output `data`.

## 8. Mediciones (macOS arm64, Node 24, snarkjs 0.7.6)

| Métrica | Valor |
|---|---|
| Restricciones del circuito `Transfer(2,2,20)` | 12.178 (6 públicas, 53 privadas) |
| ptau | `ppot_0080_15` (37,8 MB), sha256 `4a8eb5a7…272f3d`, registrado la primera vez que se usó |
| zkey / wasm | 8,6 MB / 2,5 MB |
| Generar una prueba (en caliente) | ~0,56–0,83 s |
| Verificar | ~9–10 ms |
| Sobre / script `OP_RETURN` / tx | 572 B / 576 B / 709 vB |
| Replay | ~1,3 ms por bloque más ~10 ms por transferencia verificada |

## 9. El siguiente obstáculo hacia el caso C

1. **Una prueba sucinta de que el replay es válido.** Hace falta un SNARK, recursivo o de
   *folding*, que pruebe que `R[h]` y `N` se derivan de los bloques de Bitcoin. Hoy ese
   estado solo existe como salida de un indexer. El paper lo deja abierto como el problema
   de los *light clients* (§22.2, p.39) [V].
2. **Además, una capa que lo haga cumplir en Bitcoin.** Todas las opciones de hoy suman un
   supuesto nuevo:
   - un Setup honesto más WE heurístico y no implementado (PIPEs/AADP);
   - 1 de n honesto más liquidez de operadores (BitVM2);
   - un comité t-de-n, que es una federación.

## 10. Desviaciones respecto del paper Shielded Bitcoin

| Área | Paper | ZBTC | Consecuencia |
|---|---|---|---|
| Valor | sats vía PIPEs (p.4) | unidades simuladas | no es BTC (caso B) |
| Hoja | `H_leaf(salt, h_body, j, pk_eph, ct, h_aux)` (p.15) | `cm = Poseidon(3, v, owner, rseed)` | necesaria con cifrado fuera del circuito; sin ella habría inflación |
| Cifrado | probado en el circuito | X25519 + HKDF + ChaCha20-Poly1305 fuera del circuito | un ct basura se acepta y el receptor pierde la nota |
| Claves | árbol HKDF, `pk_d` diversificadas | `owner = H(sk_spend)` más clave X25519 | sin diversificadores ni modos de divulgación |
| `ct_out` | sí (p.20) | omitido | la recuperación no trae el detalle de pagos salientes |
| Prueba | 192 B comprimida | 256 B sin comprimir | +64 B |
| Sobre | 610 B | 572 B | — |
| Setup | ceremonia (A3) | una contribución de desarrollo | quien la hizo puede falsificar pruebas y emitir valor |
| Fees | futura bóveda PIPE | una wallet bitcoind por actor | los inputs de fee vinculan publicaciones |
| Validación de puntos | — | subgrupo G2 y punto en el infinito verificados al parsear | cierra un hueco de `snarkjs`, que solo comprueba que el punto esté en la curva |

## 11. Repos evaluados (clasificados leyendo código, no README)

| Repo | Estado |
|---|---|
| `ShieldedCSV/ShieldedCSV` | Solo especificación: Rust con `unimplemented!()`, sin tests |
| `ZeroSync/ZKCoins` | Implementación parcial: SP1 con prover mock, inscripciones Taproot |
| `BitVM/zkCoins` | Experimento de recursión con Plonky2 (2024); es otro proyecto |
| `harshjv/shielded-bitcoin-poc` | Ejecutable con tests (nunca corridos en CI), Circom con 55k restricciones, peg custodial |
| `77ph/shielded-bitcoin` | Pre-alpha en Rust (arkworks, BLS12-381) |
| `ATOSHI-ORG/atoshi-privacy-circuits` | Circuitos estilo Tornado atados a un L2 EVM; 1→1 sin cambio |
| `BitVM/BitVM` | Ejecutable, de grado investigación; "DO NOT USE IN PRODUCTION" |
| `CharmsDev/charms` | Validación del lado del cliente en producción (SP1, no Circom) |

## 12. Matriz adversarial (resultados)

Ejecutada con `pnpm vitest run test/unit test/circuit test/e2e`: 14 archivos y 102 tests en
verde. La suite e2e corrió tres veces completa sin fallos intermitentes. "acc" significa
aceptado por el replay.

| Archivo | Caso | Construcción | Resultado |
|---|---|---|---|
| double-spend | a | `generateblock [A, B]`, misma nota, wallets de fee distintas | A acc · B `E_NF_SPENT` (Bob 30, Carol 0) |
| double-spend | b | `[B, A]` | B acc · A `E_NF_SPENT` |
| double-spend | c | A en H, B en H+1 | A acc · B `E_NF_SPENT` |
| double-spend | d | carrera en mempool y luego `generatetoaddress` | gana el primero en el orden del bloque; el candidato del perdedor desaparece |
| double-spend | e | `nf0 == nf1` | `E_NF_DUP` sin verificar la prueba (`verifyCalls` sin cambios) |
| soundness | a | out > in | la wallet se niega; el prover falla; `cm` reemplazado por uno de 1000 unidades → `E_PROOF` |
| soundness | b | prueba `norange` de 100 → 200 + (r−100) | verifica con la vk `norange`, `E_PROOF` con la vk principal; el suministro no cambia |
| soundness | c | π aleatoria con puntos válidos / fuera de la curva | `E_PROOF` / `E_PARSE`; el indexer sigue funcionando |
| soundness | d | un byte cambiado en anchor (misma raíz), nf, cm, epk o ct | `E_PROOF` ×5; el original intacto se acepta |
| soundness | e | front-running: se conservan nfs + π con outputs del atacante | `E_PROOF`; el original se acepta |
| soundness | f | π re-aleatorizada (mismo cuerpo) minada primero | la copia se acepta, el original da `E_NF_SPENT`; Bob recibe el mismo `cm` |
| soundness | g | ciphertext basura | **acc**; Bob no detecta nada; Σ detectada = supply − 10, exacto |
| soundness | h | anchors H−1 / H−100 / H / H−101 / S−2 | acc / acc / `E_ANCHOR` ×3; los locks pasan a rebuild y la reconstrucción se acepta |
| soundness | i | alias `nf + r` | `E_PARSE` |
| reorg | a | se revierte el bloque del gasto | `nf ∉ N`, Bob vuelve a `candidate`; re-minado con el mismo sobre → acc |
| reorg | b | el reorg invierte el ganador | gana Carol; re-minar el primero → `E_NF_SPENT`; `reconsiderblock` no cambia el digest |
| reorg | c | el bloque del anchor se reemplaza por uno vacío | `E_PROOF` (la altura existe con otra raíz); la wallet reconstruye y se acepta |
| agreement | — | indexer incremental en A a través de un reorg, replay desde cero en B (`-txindex=0`, conectado por P2P) y la CLI contra B | digest idéntico, mapa `R[h]` idéntico y rechazos idénticos |

### Hallazgos que el paper no destaca [T/I]

- **Griefing por maleabilidad.**
  - Cualquiera puede re-aleatorizar un sobre que está en la mempool y lograr que su copia
    se mine primero [T: soundness-f].
  - El valor no cambia, pero la transacción honesta se rechaza y su fee de Bitcoin se
    pierde.
  - Seguir una transferencia por txid deja de funcionar; la wallet libera sus locks por
    nullifier.
- **Las wallets de fee vinculan y encadenan publicaciones.**
  - El cambio de una transacción portadora financia la siguiente.
  - Eso crea dependencias en la capa Bitcoin cuando hay reorgs, y vincula publicaciones del
    mismo actor.
  - Es un problema de privacidad y de liveness, no de solidez.
- **Un input dummy puede quemar una nota propia.**
  - Como un dummy no prueba pertenencia, puede publicar el nullifier de otra nota del mismo
    dueño.
  - Solo puede dañarse a sí mismo: el nullifier depende de `sk_nf`.
- **Escaneo de la wallet como vector de CPU.** Un sobre en la mempool que se descifra para
  la wallet le cuesta una verificación, unos 10 ms. Un atacante que conoce la dirección puede
  forzarlo, pagando una fee de Bitcoin cada vez.
- **Setup de desarrollo.** Quien corrió `scripts/circuit.sh` puede falsificar pruebas y
  emitir valor. Las claves cambian en cada máquina, porque `zkey contribute` mezcla
  aleatoriedad del sistema operativo.

## Fuentes

- PIPEs v2: https://www.allocinit.xyz/uploads/pipesv2.pdf
- AADP: https://www.allocinit.xyz/uploads/aadp.pdf y https://github.com/alloc-init/crypto-research-aadp-estimates
- Shielded Bitcoin: https://www.allocinit.xyz/uploads/shielded-bitcoin.pdf
- Shielded CSV: https://eprint.iacr.org/2025/068 y https://github.com/ShieldedCSV/ShieldedCSV
- Groth16 weak SE: https://eprint.iacr.org/2020/811
- BIP-352: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
- Bitcoin Core 30.0, política de OP_RETURN: https://bitcoincore.org/en/releases/30.0/
- BitVM2: https://bitvm.org/bitvm2
- snarkjs CVE-2023-33252: https://advisories.gitlab.com/npm/snarkjs/CVE-2023-33252/
