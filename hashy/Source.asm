include \masm32\include\masm32rt.inc

.data
hwnd HWND ? ; handle to the console window
inpNumRead DWORD ? ; the number of events read from console input
inp INPUT_RECORD 128 dup(<>) ; events read from console input


message db 1024 dup (0), 0 ;input buffer
messageLength DWORD ?

initial_a DWORD 06a09e667h ; initial constants
initial_b DWORD 0bb67ae85h
initial_c DWORD 03c6ef372h
initial_d DWORD 0a54ff53ah
initial_e DWORD 0510e527fh
initial_f DWORD 09b05688ch
initial_g DWORD 01f83d9abh
initial_h DWORD 05be0cd19h

; k constants
K0_31 DWORD 0428a2f98h, 071374491h, 0b5c0fbcfh, 0e9b5dba5h, 03956c25bh, 059f111f1h, 0923f82a4h, 0ab1c5ed5h, 0d807aa98h, 012835b01h, 0243185beh, 0550c7dc3h, 072be5d74h, 080deb1feh, 09bdc06a7h, 0c19bf174h, 0e49b69c1h, 0efbe4786h, 00fc19dc6h, 0240ca1cch, 02de92c6fh, 04a7484aah, 05cb0a9dch, 076f988dah, 0983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h, 0c6e00bf3h, 0d5a79147h, 006ca6351h, 014292967h
K31_63 DWORD 027b70a85h, 02e1b2138h, 04d2c6dfch, 053380d13h, 0650a7354h, 0766a0abbh, 081c2c92eh, 092722c85h, 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h, 0d192e819h, 0d6990624h, 0f40e3585h, 0106aa070h, 019a4c116h, 01e376c08h, 02748774ch, 034b0bcb5h, 0391c0cb3h, 04ed8aa4ah, 05b9cca4fh, 0682e6ff3h, 0748f82eeh, 078a5636fh, 084c87814h, 08cc70208h, 090befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h

nBlock DWORD ? ; number of blocks
pMem DWORD ? ; pointer to allocated memory

taPrev DWORD ? ; the intermediate ta-th
tbPrev DWORD ?
tcPrev DWORD ?
tdPrev DWORD ?
tePrev DWORD ?
tfPrev DWORD ?
tgPrev DWORD ?
thPrev DWORD ?

pBuff db 64 dup(0), 0 ; hash string buffer
tBuff db 16 dup(0), 0 ; timer buffer
lBuff db 16 dup(0), 0

crlf db 13, 10, 0 ; next line string
timeMessage db "elapsed time: ", 0 ; strings to print V
microMessage db " micro seconds", 13, 10, "press ctrl+c to exit", 0 ; microseconds
insertMessage db "insert message to hash using SHA256: ", 0 ; prompt
lengthMessage db "/1024", 0

tFrequency LARGE_INTEGER <> ; find cpu frequency to calculate time
tStart LARGE_INTEGER <> ; start of hashy time
tEnd LARGE_INTEGER <> ; end of hash time
tElapsed db 8 dup (0),0 ; elapsed time of hash

.const
SUM0ROT1=2 ; rotating constants
SUM0ROT2=13 ;
SUM0ROT3=22 ;

SUM1ROT1=6 ; rotating constants
SUM1ROT2=11 ;
SUM1ROT3=25 ;

SIGMA0ROT1=7 ; rotating constants
SIGMA0ROT2=18 ;
SIGMA0SHIFT1=3 ;

SIGMA1ROT1=17 ;rotating constants
SIGMA1ROT2=19 ;
SIGMA1SHIFT1=10 ;

charoffset = SIZEOF DWORD + SIZEOF BOOL + SIZEOF WORD * 3 ; constant for the offset of char inside KEY_EVENT struct

MAX_CHAR = 1024
.code

strLenByTerminator proc address:DWORD ;gets the length of string by the terminator 0
	mov ebx, address ;the address of the string
	xor eax, eax

	.while BYTE PTR [ebx]!=0 ;loops until it finds the next byte 00
		inc ebx ;inc pointer
		inc eax ;inc return value
	.endw
	
	ret
strLenByTerminator endp

getNumBlock proc address:DWORD ;gets the correct number of blocks to hash by the address of the string to hash
	invoke strLenByTerminator, address ; get string length
	; calculates the correct amount of 512 bit blocks of data for the hash
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

pad512 proc address:DWORD ; pads the message into the pMem using GlobalAlloc
	LOCAL lenBytes:DWORD, numBlock:DWORD, numZero:DWORD
	
	invoke strLenByTerminator, address ; find length of message to hash
	mov lenBytes, eax
	invoke getNumBlock, address
	mov numBlock, eax
	mov ebx, 64
	mul ebx
	invoke GlobalAlloc, GPTR, eax ; allocate enough memory to store the message for calc
	mov pMem, eax
	
	xor ecx, ecx
	mov ebx, address
	.while ecx < lenBytes ;copies the string from the buffer into allocated memory
		mov dl, BYTE PTR [ebx + ecx]
		mov BYTE PTR [eax + ecx], dl
		inc ecx
	.endw
	
	mov BYTE PTR [eax + ecx], 80h ; put a bit in the end of the message
	inc ecx
	invoke getNumBlock, address ; find number of blocks
	mov ebx, 64
	mul ebx
	sub eax, lenBytes
	sub eax, 4
	mov numZero, eax

	mov ecx, lenBytes
	inc ecx
	mov eax, pMem
	.while ecx < numZero ; fills the rest of the blocks with 00 until 8 bytes from the end of the final block
		mov BYTE PTR [eax+ecx], 0h
		inc ecx
	.endw

	mov ecx, lenBytes
	inc ecx
	add ecx, numZero
	mov eax, lenBytes
	mov ebx, 8
	mul ebx ; number of bits in message to hash
	mov ebx, pMem
	
	.if eax < 65536 ; puts the length in bits at the end of the last block
		xchg al, ah ; swaps between little and big endian
		inc ecx
		mov WORD PTR [ebx + ecx], ax
	.else
		bswap eax	; swaps between little and big endian
		mov DWORD PTR [ebx + ecx], eax
	.endif

	ret
pad512 endp

; SHA256 specific calculations
chxyz proc x:DWORD, y:DWORD, z:DWORD ; (X AND Y) XOR (NOT X AND Z)
	mov eax, x
	mov ebx, y
	and eax, ebx ; (X AND Y)

	mov ecx, z
	mov edx, x
	not edx
	and edx, ecx ; (NOT X AND Y)

	xor eax, edx ; XOR

	ret
chxyz endp

; SHA256 specific calculations
majxyz proc x:DWORD, y:DWORD, z:DWORD ; (X AND Y) XOR (X AND Z) XOR (Y AND Z)
	LOCAL one:DWORD
	mov eax, x
	mov ebx, y
	and eax, ebx
	mov one, eax ; (X AND Y)

	mov eax, x
	mov ebx, z
	and eax, ebx ; (X AND Z)

	mov ecx, y
	mov edx, z
	and ecx, edx ; (Y AND Z)

	xor eax, one ; XOR
	xor eax, ecx ; XOR

	ret
majxyz endp

; SHA256 specific calculations
sum0 proc x:DWORD ; S(X, SUM0ROT1) XOR S(X, SUM0ROT2) XOR S(X, SUM0ROT3) S=rotater, R=shiftr
	mov eax, x
	ror eax, SUM0ROT1
	mov ebx, eax ; S(X, SUM0ROT1)

	mov eax, x
	ror eax, SUM0ROT2
	mov ecx, eax ; S(X, SUM0ROT2)

	mov eax, x
	ror eax, SUM0ROT3 ; S(X, SUM0ROT3)
	
	xor eax, ebx ; XOR
	xor eax, ecx ; XOR

	ret
sum0 endp

; SHA256 specific calculations
sum1 proc x:DWORD ; S(X, SUM1ROT1) XOR S(X, SUM1ROT2) XOR S(X, SUM1ROT3)
	mov eax, x
	ror eax, SUM1ROT1
	mov ebx, eax ; S(X, SUM1ROT1)

	mov eax, x
	ror eax, SUM1ROT2
	mov ecx, eax ; S(X, SUM1ROT2)

	mov eax, x
	ror eax, SUM1ROT3 ; S(X, SUM1ROT3)
	
	xor eax, ebx ; XOR
	xor eax, ecx ; XOR

	ret
sum1 endp

; SHA256 specific calculations
sigma0 proc x:DWORD ; S(X, SIGMA0ROT1) XOR S(X, SIGMA0ROT2) XOR R(X, SIGMA0SHIFT1)
	mov eax, x
	ror eax, SIGMA0ROT1
	mov ebx, eax ; S(X, SIGMA0ROT1)

	mov eax, x
	ror eax, SIGMA0ROT2
	mov ecx, eax ; S(X, SIGMA0ROT2)

	mov eax, x
	shr eax, SIGMA0SHIFT1 ; R(X, SIGMA0SHIFT1)
	
	xor eax, ebx ; XOR
	xor eax, ecx ; XOR

	ret
sigma0 endp

; SHA256 specific calculations
sigma1 proc x:DWORD ; S(X, SIGMA1ROT1) XOR S(X, SIGMA1ROT2) XOR R(X, SIGMA1SHIFT1)
	mov eax, x
	ror eax, SIGMA1ROT1
	mov ebx, eax ; S(X, SIGMA1ROT1)

	mov eax, x
	ror eax, SIGMA1ROT2
	mov ecx, eax ; S(X, SIGMA1ROT2)

	mov eax, x
	shr eax, SIGMA1SHIFT1 ; R(X, SIGMA1SHIFT1)
	
	xor eax, ebx ; XOR
	xor eax, ecx ; XOR

	ret
sigma1 endp

; SHA256 specific calculations
; recursive function 
wj proc n:DWORD, block:DWORD ; returns the message dependant function
	LOCAL one:DWORD, two:DWORD, three:DWORD
	
	.if n <= 15 ; Wj = Mj 32 bit words, stops recurssion
		mov ebx, block ; current block address
		mov ecx, n ; current index of loop
		mov eax, DWORD PTR [ebx + SIZEOF DWORD * ecx]
		bswap eax ; convert little endian big endian
	
	.else ; Wj = sigma1(Wj-2) + Wj-7 + sigma0(Wj-15) + Wj-16
		mov eax, n
		sub eax, 2
		invoke wj, eax, block ; Wj(n-2) starts recuression
		invoke sigma1, eax ; sigma1(Wj-2)
		mov one, eax
		
		mov eax, n
		sub eax, 7
		invoke wj, eax, block ; Wj(n-7) starts recuression
		mov two, eax

		mov eax, n
		sub eax, 15
		invoke wj, eax, block ; Wj(n-15) starts recurssion
		invoke sigma0, eax ; sigma0(Wj-15)
		mov three, eax

		mov eax, n
		sub eax, 16
		invoke wj, eax, block  ; Wj(n-16) starts recurssion
		
		add eax, one ; ADD
		add eax, two ; ADD
		add eax, three ; ADD

	.endif
	ret
wj endp

; SHA256 specific calculations
; recursive function
hashBlock proc block:DWORD, n:DWORD ; returns in ta-th the hash value of some message given
	LOCAL t1:DWORD, t2:DWORD, ta:DWORD, tb:DWORD, tc:DWORD, td:DWORD, te:DWORD, tf:DWORD, tg:DWORD, th:DWORD
	
	.if n==0 ;stops recuression and returns constant values
		; copy inter hash values
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

		xor ecx, ecx ; zero the index
		.while ecx < 64 ; loop 64 times
			mov ebx, th ; th

			push ebx
			push ecx
			invoke sum1, te ; sum1(te)
			pop ecx
			pop ebx
			add ebx, eax ; add th and sum1(te)

			push ebx
			push ecx
			invoke chxyz, te, tf, tg ; chxyz(te, tf, tg)
			pop ecx
			pop ebx
			add ebx, eax ; add prev and chxyz

			.if ecx < 32 ; return k constant given the current loop index
				lea edx, K0_31
				mov eax, DWORD PTR [edx + ecx*4]
			.else ; return k constant given the current loop index
				lea edx, K31_63
				mov eax, ecx
				sub eax, 32
				mov eax, DWORD PTR [edx + eax*4]
			.endif
			add ebx, eax ; add prev to returned k constant

			push ebx
			push ecx
			invoke wj, ecx, pMem ; get Wj(index)
			pop ecx
			pop ebx
			add ebx, eax ; add prev to Wj(index)

			mov t1, ebx ; move prev to t1 (temporary)
		
			push ecx
			invoke sum0, ta ; get sum0(ta)
			pop ecx
			mov ebx, eax ; move sum0(ta) to ebx reg

			push ebx
			push ecx
			invoke majxyz, ta, tb, tc ; get majxyz(ta, tb, tc)
			pop ecx
			pop ebx
			add ebx, eax ; add prev to majxyz(ta, tb, tc)

			mov t2, ebx ; move solution to t2 (temoprary)

			mov eax, tg ; th <- tg
			mov th, eax

			mov eax, tf ; tg <- tf
			mov tg, eax

			mov eax, te ; tf <- te
			mov tf, eax

			mov eax, td ; te <- td + t1
			add eax, t1
			mov te, eax

			mov eax, tc ; td <- tc
			mov td, eax

			mov eax, tb ; tc <- tb
			mov tc, eax

			mov eax, ta ; tb <- ta
			mov tb, eax

			mov eax, t1 ; ta <- t1 + t2
			add eax, t2
			mov ta, eax

			inc ecx ;increment index
		.endw

		mov eax, initial_a ; add all of calculated ta-th to given constants
		add eax, ta		   ; and store in memory as correct endian value
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
	
	.else ; if recurssion still occurs
		mov eax, n
		dec eax
		invoke hashBlock, block, eax ; start recursion of prev block
		
		mov eax, taPrev ; load to ta-th all of prev block hash resault
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
		
		xor ecx, ecx ; zero index
		.while ecx < 64 ; loop 64 times
			mov ebx, th ; th

			push ebx
			push ecx
			invoke sum1, te ; get sum1(te)
			pop ecx
			pop ebx
			add ebx, eax ; add resault to prev

			push ebx
			push ecx
			invoke chxyz, te, tf, tg ; get chxyz(te, tf, tg)
			pop ecx
			pop ebx
			add ebx, eax ; add resault to prev

			.if ecx < 32 ; get k constant of current index
				lea edx, K0_31
				mov eax, DWORD PTR [edx + ecx*4]
			.else
				lea edx, K31_63
				mov eax, ecx
				sub eax, 32
				mov eax, DWORD PTR [edx + eax*4]
			.endif
			add ebx, eax ; add constant to prev

			push ebx
			push ecx
			mov ebx, 64
			mov eax, n
			mul ebx
			add eax, block
			invoke wj, ecx, eax ; get Wj(index)
			pop ecx
			pop ebx
			add ebx, eax ; add resault to prev

			mov t1, ebx ; mov prev to t1 (temporary)

			push ecx
			invoke sum0, ta ; get sum0(ta)
			pop ecx
			mov ebx, eax ; move resault to prev

			push ebx
			push ecx
			invoke majxyz, ta, tb, tc ; get majxyz(ta, tb, tc)
			pop ecx
			pop ebx
			add ebx, eax ; add resault to prev

			mov t2, ebx ; mov prev to t2 (temporary)

			mov eax, tg ; th <- tg
			mov th, eax

			mov eax, tf ; tg <- tf
			mov tg, eax

			mov eax, te ; tf <- te
			mov tf, eax

			mov eax, td ; te <- td + t1
			add eax, t1
			mov te, eax

			mov eax, tc ; td <- tc
			mov td, eax

			mov eax, tb ; tc <- tb
			mov tc, eax

			mov eax, ta ; tb <- ta
			mov tb, eax

			mov eax, t1 ; ta <- t1 + t2
			add eax, t2
			mov ta, eax

			inc ecx ; increment index
		.endw

		mov eax, taPrev ; add all of calculated ta-th to given last block ta-th
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

	.endif
	ret
hashBlock endp

hashMess proc address:DWORD ; invokes all of hash related functions in order
	
	invoke pad512, address ; pad
	invoke getNumBlock, address ; get the number of blocks
	dec eax
	invoke hashBlock, pMem, eax ; hash the message
	
	ret
hashMess endp

printHash proc ; prints the ta-th in order
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

	lea edx, pBuff ; pointer to pBuff (buffer of the hash)
	invoke dw2hex, taPrev, edx ; make a string from value of ta
	add edx, 8 
	invoke dw2hex, tbPrev, edx ; make a string from value of tb
	add edx, 8
	invoke dw2hex, tcPrev, edx ; make a string from value of tc
	add edx, 8
	invoke dw2hex, tdPrev, edx ; make a string from value of td
	add edx, 8
	invoke dw2hex, tePrev, edx ; make a string from value of te
	add edx, 8
	invoke dw2hex, tfPrev, edx ; make a string from value of tf
	add edx, 8
	invoke dw2hex, tgPrev, edx ; make a string from value of tg
	add edx, 8
	invoke dw2hex, thPrev, edx ; make a string from value of th
	
	; the hex values of hash should be written in lower case
	; but dw2hex outputs them as upper case
	xor ecx, ecx ; zero index
	.while ecx < 64 ; loop 64 times
		lea ebx, pBuff ; pointer to the buffer
		.if BYTE PTR [ebx+ecx] > 60 ; make all of the hex letters lower case
			mov al, BYTE PTR [ebx+ecx]
			add al, 32
			mov BYTE PTR [ebx+ecx], al
		.endif
		inc ecx ; increment index
	.endw

	invoke StdOut, addr pBuff ; print the hash buffer
	invoke StdOut, addr crlf ; print new line

	ret
printHash endp

; calculates the time difference between hash start and stop then divides by cpu clock count
; per second to find time in microsecond it took to hash
calcTime proc
	
	lea ebx, tEnd ; ticks of end
	mov eax, DWORD PTR [ebx]
	lea ebx, tStart ; ticks of start
	sub eax, DWORD PTR [ebx]
	lea ebx, tEnd
	mov ebx, DWORD PTR [ebx+4]
	lea ecx, tStart
	sbb ebx, DWORD PTR [ecx+4]
	mov ebx, 0000f4240h ; multiplies to sort out unit conversions
	mul ebx
	
	lea ebx, tElapsed
	mov DWORD PTR [ebx], edx
	mov DWORD PTR [ebx+4], eax
	lea ebx, tFrequency
	mov ebx, tFrequency.LowPart
	div ebx ; divides the ticks in the frequency to get time
	invoke dwtoa, eax, addr tBuff ; outputs number of microseconds to tBuff
	
	ret
calcTime endp

update proc ; updates the user interface when key is pressed down
	
	invoke ReadConsoleInput, hwnd, addr inp, 128, addr inpNumRead ; read the input to the console window
	
	xor ecx, ecx ; zero out index
	.while ecx < inpNumRead
		lea ebx, inp
	
		.if WORD PTR [ebx+ecx] == KEY_EVENT ; if the input was a key event
			.if BYTE PTR [ebx+ecx+SIZEOF DWORD] == 1 ; if the key was pressed down
				push ecx
				invoke ClearScreen ; clear the screen of the console
				invoke strLenByTerminator, addr message ; find length of buffer
				pop ecx
				lea edx, message
				lea ebx, inp
				add ebx, ecx
				add ebx, charoffset
				mov bl, BYTE PTR [ebx] ; find last character from the input struct
				
				.if bl == 8 ; back space pressed
					mov BYTE PTR [edx+eax-1], 0 ; delete last char from buffer
					invoke strLenByTerminator, addr message
					mov messageLength, eax
					mov eax, 1 ; return that an update has been made
					
					ret
				.else
					.if messageLength < MAX_CHAR
						.if bl == 13 ; enter pressed
							mov BYTE PTR [edx+eax], 10 ; add \n char
							invoke strLenByTerminator, addr message
							mov messageLength, eax ; update the length of the message
							mov eax, 1 ; return that an update has been made
						
							ret
						.else
							mov BYTE PTR [edx+eax], BYTE PTR bl ; add the last char to buffer
							invoke strLenByTerminator, addr message
							mov messageLength, eax ; update the length of the message
							mov eax, 1 ; return that an update has been made
				
							ret
						.endif
					.else
						mov eax, 1
						ret
					.endif
				.endif
			.endif
		.endif
		inc ecx ; incerement index
	.endw

	mov eax, 0 ; return that no update has been made to buffer
	ret
update endp

printCharCount proc
	
	invoke dwtoa, messageLength, addr lBuff ; length of current message to hash
	invoke StdOut, addr lBuff ; prints the length
	invoke StdOut, addr lengthMessage ; prints /1024
	invoke StdOut, addr crlf ; new line

	ret
printCharCount endp

calcHash proc
	invoke StdOut, addr insertMessage ; prompts the user
	invoke StdOut, addr crlf ;print new line
	invoke StdOut, addr message ; print the buffer
	invoke StdOut, addr crlf ; print new line
	invoke printCharCount ; print char count

	invoke QueryPerformanceFrequency, addr tFrequency ; gets the cpu frequency
	invoke QueryPerformanceCounter, addr tStart ; starts the tick count
	invoke hashMess, addr message ; hashes the message from the buffer
	invoke QueryPerformanceCounter, addr tEnd ; stops the timer of ticks
	invoke calcTime ; subtructs the tick interval

	invoke printHash ; prints the resault of the SHA256 function

	invoke StdOut, addr timeMessage ; prints elapsed time: 
	invoke StdOut, addr tBuff ; prints time in micro seconds of hashing
	invoke StdOut, addr microMessage ; prints micro seconds
	ret
calcHash endp

main proc ; main loop
	invoke GetStdHandle, STD_INPUT_HANDLE ; gets the handle to console window
	mov hwnd, eax

	xor ecx, ecx ; zero out index
	mov eax, 1 ; print the hash of "" for the first time
	.while ecx == 0 ; infinite loop
		.if eax == 1 ; check if the buffer updated
			invoke calcHash ; calculate the hash of the buffer
		.endif
		invoke update ; check for updates in the buffer
		xor ecx, ecx ; infinite loop
	.endw

	invoke ExitProcess, 0 ; exit the process correctly
main endp

end main