include \masm32\include\masm32rt.inc

.data
message db 256 dup (0),0
buff_512 db 64 dup (?), 0
initial_a DWORD 06a09e667h
initial_b DWORD 0bb67ae85h
initial_c DWORD 03c6ef372h
initial_d DWORD 0a54ff53ah
initial_e DWORD 0510e527fh
initial_f DWORD 09b05688ch
initial_g DWORD 01f83d9abh
initial_h DWORD 05be0cd19h
K0_31 DWORD 0428a2f98h, 071374491h, 0b5c0fbcfh, 0e9b5dba5h, 03956c25bh, 059f111f1h, 0923f82a4h, 0ab1c5ed5h, 0d807aa98h, 012835b01h, 0243185beh, 0550c7dc3h, 072be5d74h, 080deb1feh, 09bdc06a7h, 0c19bf174h, 0e49b69c1h, 0efbe4786h, 00fc19dc6h, 0240ca1cch, 02de92c6fh, 04a7484aah, 05cb0a9dch, 076f988dah, 0983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h, 0c6e00bf3h, 0d5a79147h, 006ca6351h, 014292967h
K31_63 DWORD 027b70a85h, 02e1b2138h, 04d2c6dfch, 053380d13h, 0650a7354h, 0766a0abbh, 081c2c92eh, 092722c85h, 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h, 0d192e819h, 0d6990624h, 0f40e3585h, 0106aa070h, 019a4c116h, 01e376c08h, 02748774ch, 034b0bcb5h, 0391c0cb3h, 04ed8aa4ah, 05b9cca4fh, 0682e6ff3h, 0748f82eeh, 078a5636fh, 084c87814h, 08cc70208h, 090befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h
nBlock DWORD ?
pMem DWORD ?
taPrev DWORD 06a09e667h
tbPrev DWORD 0bb67ae85h
tcPrev DWORD 03c6ef372h
tdPrev DWORD 0a54ff53ah
tePrev DWORD 0510e527fh
tfPrev DWORD 09b05688ch
tgPrev DWORD 01f83d9abh
thPrev DWORD 05be0cd19h
pBuff db 64 dup(0), 0
tBuff db 16 dup(0), 0
crlf db 13, 10, 0
timeMessage db "elapsed time: ", 0
miliMessage db " micro seconds", 0
insertMessage db "insert message to hash using SHA256: ", 0
tFrequency LARGE_INTEGER <>
tStart LARGE_INTEGER <>
tEnd LARGE_INTEGER <>
tElapsed db 8 dup (0),0
.code

getMessage proc
	invoke StdIn, addr message, 256
	ret
getMessage endp

strLenByTerminator proc address:DWORD
	mov ebx, address
	xor eax, eax
	.while BYTE PTR [ebx]!=0
		inc ebx
		inc eax
	.endw
	ret
strLenByTerminator endp

getNumBlock proc address:DWORD
	invoke strLenByTerminator, address
	xor edx, edx
	mov ebx, 64
	div ebx
	.if edx < 56
		inc eax
	.else
		add eax, 2
	.endif

	ret
getNumBlock endp

pad512 proc address:DWORD
	LOCAL lenBytes:DWORD, numBlock:DWORD, numZero:DWORD
	invoke strLenByTerminator, address
	mov lenBytes, eax
	invoke getNumBlock, address
	mov numBlock, eax
	mov ebx, 64
	mul ebx
	invoke GlobalAlloc, GPTR, eax
	mov pMem, eax
	xor ecx, ecx
	mov ebx, address
	.while ecx < lenBytes
		mov dl, BYTE PTR [ebx + ecx]
		mov BYTE PTR [eax + ecx], dl
		inc ecx
	.endw
	mov BYTE PTR [eax + ecx], 80h
	inc ecx
	invoke getNumBlock, address
	mov ebx, 64
	mul ebx
	sub eax, lenBytes
	sub eax, 4
	mov numZero, eax

	mov ecx, lenBytes
	inc ecx
	mov eax, pMem
	.while ecx < numZero
		mov BYTE PTR [eax+ecx], 0h
		inc ecx
	.endw
	mov ecx, lenBytes
	inc ecx
	add ecx, numZero
	mov eax, lenBytes
	mov ebx, 8
	mul ebx
	mov ebx, pMem
	.if eax < 65536
		xchg al, ah
		inc ecx
		mov WORD PTR [ebx + ecx], ax
	.else
		bswap eax
		mov DWORD PTR [ebx + ecx], eax
	.endif

	ret
pad512 endp

chxyz proc x:DWORD, y:DWORD, z:DWORD ; (X AND Y) XOR (NOT X AND Z)
	mov eax, x
	mov ebx, y
	and eax, ebx

	mov ecx, z
	mov edx, x
	not edx
	and edx, ecx

	xor eax, edx

	ret
chxyz endp

majxyz proc x:DWORD, y:DWORD, z:DWORD ; (X AND Y) XOR (X AND Z) XOR (Y AND Z)
	LOCAL one:DWORD
	mov eax, x
	mov ebx, y
	and eax, ebx
	mov one, eax

	mov eax, x
	mov ebx, z
	and eax, ebx

	mov ecx, y
	mov edx, z
	and ecx, edx

	xor eax, one
	xor eax, ecx

	ret
majxyz endp

sum0 proc x:DWORD ; (S(X, 2)) XOR (S(X, 13)) XOR (S(X, 22))
	mov eax, x
	ror eax, 2
	mov ebx, eax

	mov eax, x
	ror eax, 13
	mov ecx, eax

	mov eax, x
	ror eax, 22
	
	xor eax, ebx
	xor eax, ecx

	ret
sum0 endp

sum1 proc x:DWORD ; (S(X, 6)) XOR (S(X, 11)) XOR (S(X, 25))
	mov eax, x
	ror eax, 6
	mov ebx, eax

	mov eax, x
	ror eax, 11
	mov ecx, eax

	mov eax, x
	ror eax, 25
	
	xor eax, ebx
	xor eax, ecx

	ret
sum1 endp

sigma0 proc x:DWORD ; (S(X, 7)) XOR (S(X, 18)) XOR (R(X, 3))
	mov eax, x
	ror eax, 7
	mov ebx, eax

	mov eax, x
	ror eax, 18
	mov ecx, eax

	mov eax, x
	shr eax, 3
	
	xor eax, ebx
	xor eax, ecx

	ret
sigma0 endp

sigma1 proc x:DWORD ; (S(X, 17)) XOR (S(X, 19)) XOR (R(X, 10))
	mov eax, x
	ror eax, 17
	mov ebx, eax

	mov eax, x
	ror eax, 19
	mov ecx, eax

	mov eax, x
	shr eax, 10
	
	xor eax, ebx
	xor eax, ecx

	ret
sigma1 endp

wj proc n:DWORD, block:DWORD
	LOCAL one:DWORD, two:DWORD, three:DWORD
	.if n <= 15 ; Wj = Mj 32 bit words
		mov ebx, block
		mov ecx, n
		mov eax, DWORD PTR [ebx + SIZEOF DWORD * ecx]
		bswap eax
	.else ; Wj = sigma1(Wj-2) + Wj-7 + sigma0(Wj-15) + Wj-16
		mov eax, n
		sub eax, 2
		invoke wj, eax, block
		invoke sigma1, eax
		mov one, eax
		
		mov eax, n
		sub eax, 7
		invoke wj, eax, block
		mov two, eax

		mov eax, n
		sub eax, 15
		invoke wj, eax, block
		invoke sigma0, eax
		mov three, eax

		mov eax, n
		sub eax, 16
		invoke wj, eax, block
		
		add eax, one
		add eax, two
		add eax, three		

	.endif
	
	ret
wj endp

hashBlock proc block:DWORD, n:DWORD
	LOCAL t1:DWORD, t2:DWORD, ta:DWORD, tb:DWORD, tc:DWORD, td:DWORD, te:DWORD, tf:DWORD, tg:DWORD, th:DWORD
	.if n==0
		mov eax, initial_a
		mov ta, eax
		mov eax, initial_b
		mov tb, eax
		mov eax, initial_c
		mov tc, eax
		mov eax, initial_d
		mov td, eax
		mov eax, initial_e
		mov te, eax
		mov eax, initial_f
		mov tf, eax
		mov eax, initial_g
		mov tg, eax
		mov eax, initial_h
		mov th, eax

		xor ecx, ecx
		.while ecx < 64
			mov ebx, th
			push ebx
			push ecx
			invoke sum1, te
			pop ecx
			pop ebx
			add ebx, eax
			push ebx
			push ecx
			invoke chxyz, te, tf, tg
			pop ecx
			pop ebx
			add ebx, eax
			.if ecx < 32
				lea edx, K0_31
				mov eax, DWORD PTR [edx + ecx*4]
			.else
				lea edx, K31_63
				mov eax, ecx
				sub eax, 32
				mov eax, DWORD PTR [edx + eax*4]
			.endif
			add ebx, eax
			push ebx
			push ecx
			invoke wj, ecx, pMem
			pop ecx
			pop ebx
			add ebx, eax
			mov t1, ebx
		
			push ecx
			invoke sum0, ta
			pop ecx
			mov ebx, eax
			push ebx
			push ecx
			invoke majxyz, ta, tb, tc
			pop ecx
			pop ebx
			add ebx, eax
			mov t2, ebx

			mov eax, tg
			mov th, eax

			mov eax, tf
			mov tg, eax

			mov eax, te
			mov tf, eax

			mov eax, td
			add eax, t1
			mov te, eax

			mov eax, tc
			mov td, eax

			mov eax, tb
			mov tc, eax

			mov eax, ta
			mov tb, eax

			mov eax, t1
			add eax, t2
			mov ta, eax

			inc ecx
		.endw
		mov eax, initial_a
		add eax, ta
		bswap eax
		mov taPrev, eax
		mov eax, initial_b
		add eax, tb
		bswap eax
		mov tbPrev, eax
		mov eax, initial_c
		add eax, tc
		bswap eax
		mov tcPrev, eax
		mov eax, initial_d
		add eax, td
		bswap eax
		mov tdPrev, eax
		mov eax, initial_e
		add eax, te
		bswap eax
		mov tePrev, eax
		mov eax, initial_f
		add eax, tf
		bswap eax
		mov tfPrev, eax
		mov eax, initial_g
		add eax, tg
		bswap eax
		mov tgPrev, eax
		mov eax, initial_h
		add eax, th
		bswap eax
		mov thPrev, eax
		lea edx, taPrev
	.else
		mov eax, n
		dec eax
		invoke hashBlock, block, eax
		
		mov eax, taPrev
		bswap eax
		mov ta, eax
		mov eax, tbPrev
		bswap eax
		mov tb, eax
		mov eax, tcPrev
		bswap eax
		mov tc, eax
		mov eax, tdPrev
		bswap eax
		mov td, eax
		mov eax, tePrev
		bswap eax
		mov te, eax
		mov eax, tfPrev
		bswap eax
		mov tf, eax
		mov eax, tgPrev
		bswap eax
		mov tg, eax
		mov eax, thPrev
		bswap eax
		mov th, eax
		
		xor ecx, ecx
		.while ecx < 64
			mov ebx, th
			push ebx
			push ecx
			invoke sum1, te
			pop ecx
			pop ebx
			add ebx, eax
			push ebx
			push ecx
			invoke chxyz, te, tf, tg
			pop ecx
			pop ebx
			add ebx, eax
			.if ecx < 32
				lea edx, K0_31
				mov eax, DWORD PTR [edx + ecx*4]
			.else
				lea edx, K31_63
				mov eax, ecx
				sub eax, 32
				mov eax, DWORD PTR [edx + eax*4]
			.endif
			add ebx, eax
			push ebx
			push ecx
			mov ebx, 64
			mov eax, n
			mul ebx
			add eax, block
			invoke wj, ecx, eax
			pop ecx
			pop ebx
			add ebx, eax
			mov t1, ebx

			push ecx
			invoke sum0, ta
			pop ecx
			mov ebx, eax
			push ebx
			push ecx
			invoke majxyz, ta, tb, tc
			pop ecx
			pop ebx
			add ebx, eax
			mov t2, ebx

			mov eax, tg
			mov th, eax

			mov eax, tf
			mov tg, eax

			mov eax, te
			mov tf, eax

			mov eax, td
			add eax, t1
			mov te, eax

			mov eax, tc
			mov td, eax

			mov eax, tb
			mov tc, eax

			mov eax, ta
			mov tb, eax

			mov eax, t1
			add eax, t2
			mov ta, eax

			inc ecx
		.endw

		mov eax, taPrev
		bswap eax
		add eax, ta
		bswap eax
		mov taPrev, eax
		mov eax, tbPrev
		bswap eax
		add eax, tb
		bswap eax
		mov tbPrev, eax
		mov eax, tcPrev
		bswap eax
		add eax, tc
		bswap eax
		mov tcPrev, eax
		mov eax, tdPrev
		bswap eax
		add eax, td
		bswap eax
		mov tdPrev, eax
		mov eax, tePrev
		bswap eax
		add eax, te
		bswap eax
		mov tePrev, eax
		mov eax, tfPrev
		bswap eax
		add eax, tf
		bswap eax
		mov tfPrev, eax
		mov eax, tgPrev
		bswap eax
		add eax, tg
		bswap eax
		mov tgPrev, eax
		mov eax, thPrev
		bswap eax
		add eax, th
		bswap eax
		mov thPrev, eax
		lea edx, taPrev

	.endif
	;loop 64 times:
	;	T1 <= Hi-1 + sum1(Ej-1) + chxyz(Ej-1, Fj-1, Gj-1) + Kj + Wj
	;	T2 <= sum0(Aj-1) + majxyz(Aj-1, Bj-1, Cj-1)
	;	Hj <= Gj-1
	;	Gj <= Fj-1
	;	fj <= Ej-1
	;	Ej <= Dj-1 + T1
	;	Dj <= Cj-1
	;	Cj <= Bj-1
	;	Bj <= Aj-1
	;	Aj <= T1 + T2
	

	ret
hashBlock endp

hashMess proc address:DWORD
	invoke pad512, address
	invoke getNumBlock, address
	dec eax
	invoke hashBlock, pMem, eax
	ret
hashMess endp

printHash proc 
	mov eax, taPrev
	bswap eax
	mov taPrev, eax
	mov eax, tbPrev
	bswap eax
	mov tbPrev, eax
	mov eax, tcPrev
	bswap eax
	mov tcPrev, eax
	mov eax, tdPrev
	bswap eax
	mov tdPrev, eax
	mov eax, tePrev
	bswap eax
	mov tePrev, eax
	mov eax, tfPrev
	bswap eax
	mov tfPrev, eax
	mov eax, tgPrev
	bswap eax
	mov tgPrev, eax
	mov eax, thPrev
	bswap eax
	mov thPrev, eax

	lea edx, pBuff
	invoke dw2hex, taPrev, edx
	add edx, 8
	invoke dw2hex, tbPrev, edx
	add edx, 8
	invoke dw2hex, tcPrev, edx
	add edx, 8
	invoke dw2hex, tdPrev, edx
	add edx, 8
	invoke dw2hex, tePrev, edx
	add edx, 8
	invoke dw2hex, tfPrev, edx
	add edx, 8
	invoke dw2hex, tgPrev, edx
	add edx, 8
	invoke dw2hex, thPrev, edx
	xor ecx, ecx
	.while ecx < 64
		lea ebx, pBuff
		.if BYTE PTR [ebx+ecx] > 60
			mov al, BYTE PTR [ebx+ecx]
			add al, 32
			mov BYTE PTR [ebx+ecx], al
		.endif
		inc ecx
	.endw

	invoke StdOut, addr pBuff
	invoke StdOut, addr crlf

	ret
printHash endp

carrySub proc
	lea ebx, tEnd
	mov eax, DWORD PTR [ebx]
	lea ebx, tStart
	sub eax, DWORD PTR [ebx]
	lea ebx, tEnd
	mov ebx, DWORD PTR [ebx+4]
	lea ecx, tStart
	sbb ebx, DWORD PTR [ecx+4]
	mov ebx, 0000f4240h
	mul ebx
	lea ebx, tElapsed
	mov DWORD PTR [ebx], edx
	mov DWORD PTR [ebx+4], eax
	lea ebx, tFrequency
	mov ebx, tFrequency.LowPart
	div ebx
	invoke dwtoa, eax, addr tBuff
	ret
carrySub endp

main proc
	xor ecx, ecx
	.while ecx==0
		invoke StdOut, addr insertMessage
		invoke StdOut, addr crlf
		invoke getMessage
		invoke QueryPerformanceFrequency, addr tFrequency
		invoke QueryPerformanceCounter, addr tStart
		invoke hashMess, addr message
		invoke QueryPerformanceCounter, addr tEnd
		invoke carrySub
		invoke printHash
		invoke StdOut, addr timeMessage
		invoke StdOut, addr tBuff
		invoke StdOut, addr miliMessage
		invoke StdOut, addr crlf
		invoke StdOut, addr crlf
		xor ecx, ecx
	.endw
	inkey "press any button to continue"
	invoke ExitProcess, 0
main endp


end main