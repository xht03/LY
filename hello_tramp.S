
./bin/hello_tramp:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 2f 00 00 	mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 9a 2f 00 00    	push   0x2f9a(%rip)        # 3fc0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 9c 2f 00 00    	jmp    *0x2f9c(%rip)        # 3fc8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)
    1030:	f3 0f 1e fa          	endbr64
    1034:	68 00 00 00 00       	push   $0x0
    1039:	e9 e2 ff ff ff       	jmp    1020 <_init+0x20>
    103e:	66 90                	xchg   %ax,%ax

Disassembly of section .plt.got:

0000000000001040 <__cxa_finalize@plt>:
    1040:	f3 0f 1e fa          	endbr64
    1044:	ff 25 ae 2f 00 00    	jmp    *0x2fae(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    104a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001050 <puts@plt>:
    1050:	f3 0f 1e fa          	endbr64
    1054:	ff 25 76 2f 00 00    	jmp    *0x2f76(%rip)        # 3fd0 <puts@GLIBC_2.2.5>
    105a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001060 <_start>:
    1060:	f3 0f 1e fa          	endbr64
    1064:	31 ed                	xor    %ebp,%ebp
    1066:	49 89 d1             	mov    %rdx,%r9
    1069:	5e                   	pop    %rsi
    106a:	48 89 e2             	mov    %rsp,%rdx
    106d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1071:	50                   	push   %rax
    1072:	54                   	push   %rsp
    1073:	45 31 c0             	xor    %r8d,%r8d
    1076:	31 c9                	xor    %ecx,%ecx
    1078:	48 8d 3d ca 00 00 00 	lea    0xca(%rip),%rdi        # 1149 <main>
    107f:	ff 15 53 2f 00 00    	call   *0x2f53(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.34>
    1085:	f4                   	hlt
    1086:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    108d:	00 00 00 

0000000000001090 <deregister_tm_clones>:
    1090:	48 8d 3d 79 2f 00 00 	lea    0x2f79(%rip),%rdi        # 4010 <__TMC_END__>
    1097:	48 8d 05 72 2f 00 00 	lea    0x2f72(%rip),%rax        # 4010 <__TMC_END__>
    109e:	48 39 f8             	cmp    %rdi,%rax
    10a1:	74 15                	je     10b8 <deregister_tm_clones+0x28>
    10a3:	48 8b 05 36 2f 00 00 	mov    0x2f36(%rip),%rax        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    10aa:	48 85 c0             	test   %rax,%rax
    10ad:	74 09                	je     10b8 <deregister_tm_clones+0x28>
    10af:	ff e0                	jmp    *%rax
    10b1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10b8:	c3                   	ret
    10b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010c0 <register_tm_clones>:
    10c0:	48 8d 3d 49 2f 00 00 	lea    0x2f49(%rip),%rdi        # 4010 <__TMC_END__>
    10c7:	48 8d 35 42 2f 00 00 	lea    0x2f42(%rip),%rsi        # 4010 <__TMC_END__>
    10ce:	48 29 fe             	sub    %rdi,%rsi
    10d1:	48 89 f0             	mov    %rsi,%rax
    10d4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10d8:	48 c1 f8 03          	sar    $0x3,%rax
    10dc:	48 01 c6             	add    %rax,%rsi
    10df:	48 d1 fe             	sar    $1,%rsi
    10e2:	74 14                	je     10f8 <register_tm_clones+0x38>
    10e4:	48 8b 05 05 2f 00 00 	mov    0x2f05(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable@Base>
    10eb:	48 85 c0             	test   %rax,%rax
    10ee:	74 08                	je     10f8 <register_tm_clones+0x38>
    10f0:	ff e0                	jmp    *%rax
    10f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    10f8:	c3                   	ret
    10f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001100 <__do_global_dtors_aux>:
    1100:	f3 0f 1e fa          	endbr64
    1104:	80 3d 05 2f 00 00 00 	cmpb   $0x0,0x2f05(%rip)        # 4010 <__TMC_END__>
    110b:	75 2b                	jne    1138 <__do_global_dtors_aux+0x38>
    110d:	55                   	push   %rbp
    110e:	48 83 3d e2 2e 00 00 	cmpq   $0x0,0x2ee2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1115:	00 
    1116:	48 89 e5             	mov    %rsp,%rbp
    1119:	74 0c                	je     1127 <__do_global_dtors_aux+0x27>
    111b:	48 8b 3d e6 2e 00 00 	mov    0x2ee6(%rip),%rdi        # 4008 <__dso_handle>
    1122:	e8 19 ff ff ff       	call   1040 <__cxa_finalize@plt>
    1127:	e8 64 ff ff ff       	call   1090 <deregister_tm_clones>
    112c:	c6 05 dd 2e 00 00 01 	movb   $0x1,0x2edd(%rip)        # 4010 <__TMC_END__>
    1133:	5d                   	pop    %rbp
    1134:	c3                   	ret
    1135:	0f 1f 00             	nopl   (%rax)
    1138:	c3                   	ret
    1139:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001140 <frame_dummy>:
    1140:	f3 0f 1e fa          	endbr64
    1144:	e9 77 ff ff ff       	jmp    10c0 <register_tm_clones>

0000000000001149 <main>:
    1149:	f3 0f 1e fa          	endbr64
    114d:	55                   	push   %rbp
    114e:	48 89 e5             	mov    %rsp,%rbp
    1151:	48 8d 05 ac 0e 00 00 	lea    0xeac(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    1158:	48 89 c7             	mov    %rax,%rdi
    115b:	e8 f0 fe ff ff       	call   1050 <puts@plt>
    1160:	b8 00 00 00 00       	mov    $0x0,%eax
    1165:	5d                   	pop    %rbp
    1166:	c3                   	ret

Disassembly of section .fini:

0000000000001168 <_fini>:
    1168:	f3 0f 1e fa          	endbr64
    116c:	48 83 ec 08          	sub    $0x8,%rsp
    1170:	48 83 c4 08          	add    $0x8,%rsp
    1174:	c3                   	ret

Disassembly of section .tramp:

0000000000005000 <.tramp>:
	...
    56e0:	1b 00                	sbb    (%rax),%eax
    56e2:	00 00                	add    %al,(%rax)
    56e4:	01 00                	add    %eax,(%rax)
    56e6:	00 00                	add    %al,(%rax)
    56e8:	02 00                	add    (%rax),%al
    56ea:	00 00                	add    %al,(%rax)
    56ec:	00 00                	add    %al,(%rax)
    56ee:	00 00                	add    %al,(%rax)
    56f0:	50                   	push   %rax
    56f1:	03 00                	add    (%rax),%eax
    56f3:	00 00                	add    %al,(%rax)
    56f5:	00 00                	add    %al,(%rax)
    56f7:	00 50 03             	add    %dl,0x3(%rax)
    56fa:	00 00                	add    %al,(%rax)
    56fc:	00 00                	add    %al,(%rax)
    56fe:	00 00                	add    %al,(%rax)
    5700:	1c 00                	sbb    $0x0,%al
	...
    570e:	00 00                	add    %al,(%rax)
    5710:	01 00                	add    %eax,(%rax)
	...
    571e:	00 00                	add    %al,(%rax)
    5720:	23 00                	and    (%rax),%eax
    5722:	00 00                	add    %al,(%rax)
    5724:	07                   	(bad)
    5725:	00 00                	add    %al,(%rax)
    5727:	00 02                	add    %al,(%rdx)
    5729:	00 00                	add    %al,(%rax)
    572b:	00 00                	add    %al,(%rax)
    572d:	00 00                	add    %al,(%rax)
    572f:	00 70 03             	add    %dh,0x3(%rax)
    5732:	00 00                	add    %al,(%rax)
    5734:	00 00                	add    %al,(%rax)
    5736:	00 00                	add    %al,(%rax)
    5738:	70 03                	jo     573d <_end+0x1725>
    573a:	00 00                	add    %al,(%rax)
    573c:	00 00                	add    %al,(%rax)
    573e:	00 00                	add    %al,(%rax)
    5740:	30 00                	xor    %al,(%rax)
	...
    574e:	00 00                	add    %al,(%rax)
    5750:	08 00                	or     %al,(%rax)
	...
    575e:	00 00                	add    %al,(%rax)
    5760:	36 00 00             	ss add %al,(%rax)
    5763:	00 07                	add    %al,(%rdi)
    5765:	00 00                	add    %al,(%rax)
    5767:	00 02                	add    %al,(%rdx)
    5769:	00 00                	add    %al,(%rax)
    576b:	00 00                	add    %al,(%rax)
    576d:	00 00                	add    %al,(%rax)
    576f:	00 a0 03 00 00 00    	add    %ah,0x3(%rax)
    5775:	00 00                	add    %al,(%rax)
    5777:	00 a0 03 00 00 00    	add    %ah,0x3(%rax)
    577d:	00 00                	add    %al,(%rax)
    577f:	00 24 00             	add    %ah,(%rax,%rax,1)
	...
    578e:	00 00                	add    %al,(%rax)
    5790:	04 00                	add    $0x0,%al
	...
    579e:	00 00                	add    %al,(%rax)
    57a0:	49 00 00             	rex.WB add %al,(%r8)
    57a3:	00 07                	add    %al,(%rdi)
    57a5:	00 00                	add    %al,(%rax)
    57a7:	00 02                	add    %al,(%rdx)
    57a9:	00 00                	add    %al,(%rax)
    57ab:	00 00                	add    %al,(%rax)
    57ad:	00 00                	add    %al,(%rax)
    57af:	00 c4                	add    %al,%ah
    57b1:	03 00                	add    (%rax),%eax
    57b3:	00 00                	add    %al,(%rax)
    57b5:	00 00                	add    %al,(%rax)
    57b7:	00 c4                	add    %al,%ah
    57b9:	03 00                	add    (%rax),%eax
    57bb:	00 00                	add    %al,(%rax)
    57bd:	00 00                	add    %al,(%rax)
    57bf:	00 20                	add    %ah,(%rax)
	...
    57cd:	00 00                	add    %al,(%rax)
    57cf:	00 04 00             	add    %al,(%rax,%rax,1)
	...
    57de:	00 00                	add    %al,(%rax)
    57e0:	57                   	push   %rdi
    57e1:	00 00                	add    %al,(%rax)
    57e3:	00 f6                	add    %dh,%dh
    57e5:	ff                   	(bad)
    57e6:	ff 6f 02             	ljmp   *0x2(%rdi)
    57e9:	00 00                	add    %al,(%rax)
    57eb:	00 00                	add    %al,(%rax)
    57ed:	00 00                	add    %al,(%rax)
    57ef:	00 e8                	add    %ch,%al
    57f1:	03 00                	add    (%rax),%eax
    57f3:	00 00                	add    %al,(%rax)
    57f5:	00 00                	add    %al,(%rax)
    57f7:	00 e8                	add    %ch,%al
    57f9:	03 00                	add    (%rax),%eax
    57fb:	00 00                	add    %al,(%rax)
    57fd:	00 00                	add    %al,(%rax)
    57ff:	00 24 00             	add    %ah,(%rax,%rax,1)
    5802:	00 00                	add    %al,(%rax)
    5804:	00 00                	add    %al,(%rax)
    5806:	00 00                	add    %al,(%rax)
    5808:	06                   	(bad)
    5809:	00 00                	add    %al,(%rax)
    580b:	00 00                	add    %al,(%rax)
    580d:	00 00                	add    %al,(%rax)
    580f:	00 08                	add    %cl,(%rax)
	...
    581d:	00 00                	add    %al,(%rax)
    581f:	00 61 00             	add    %ah,0x0(%rcx)
    5822:	00 00                	add    %al,(%rax)
    5824:	0b 00                	or     (%rax),%eax
    5826:	00 00                	add    %al,(%rax)
    5828:	02 00                	add    (%rax),%al
    582a:	00 00                	add    %al,(%rax)
    582c:	00 00                	add    %al,(%rax)
    582e:	00 00                	add    %al,(%rax)
    5830:	10 04 00             	adc    %al,(%rax,%rax,1)
    5833:	00 00                	add    %al,(%rax)
    5835:	00 00                	add    %al,(%rax)
    5837:	00 10                	add    %dl,(%rax)
    5839:	04 00                	add    $0x0,%al
    583b:	00 00                	add    %al,(%rax)
    583d:	00 00                	add    %al,(%rax)
    583f:	00 a8 00 00 00 00    	add    %ch,0x0(%rax)
    5845:	00 00                	add    %al,(%rax)
    5847:	00 07                	add    %al,(%rdi)
    5849:	00 00                	add    %al,(%rax)
    584b:	00 01                	add    %al,(%rcx)
    584d:	00 00                	add    %al,(%rax)
    584f:	00 08                	add    %cl,(%rax)
    5851:	00 00                	add    %al,(%rax)
    5853:	00 00                	add    %al,(%rax)
    5855:	00 00                	add    %al,(%rax)
    5857:	00 18                	add    %bl,(%rax)
    5859:	00 00                	add    %al,(%rax)
    585b:	00 00                	add    %al,(%rax)
    585d:	00 00                	add    %al,(%rax)
    585f:	00 69 00             	add    %ch,0x0(%rcx)
    5862:	00 00                	add    %al,(%rax)
    5864:	03 00                	add    (%rax),%eax
    5866:	00 00                	add    %al,(%rax)
    5868:	02 00                	add    (%rax),%al
    586a:	00 00                	add    %al,(%rax)
    586c:	00 00                	add    %al,(%rax)
    586e:	00 00                	add    %al,(%rax)
    5870:	b8 04 00 00 00       	mov    $0x4,%eax
    5875:	00 00                	add    %al,(%rax)
    5877:	00 b8 04 00 00 00    	add    %bh,0x4(%rax)
    587d:	00 00                	add    %al,(%rax)
    587f:	00 8d 00 00 00 00    	add    %cl,0x0(%rbp)
	...
    588d:	00 00                	add    %al,(%rax)
    588f:	00 01                	add    %al,(%rcx)
	...
    589d:	00 00                	add    %al,(%rax)
    589f:	00 71 00             	add    %dh,0x0(%rcx)
    58a2:	00 00                	add    %al,(%rax)
    58a4:	ff                   	(bad)
    58a5:	ff                   	(bad)
    58a6:	ff 6f 02             	ljmp   *0x2(%rdi)
    58a9:	00 00                	add    %al,(%rax)
    58ab:	00 00                	add    %al,(%rax)
    58ad:	00 00                	add    %al,(%rax)
    58af:	00 46 05             	add    %al,0x5(%rsi)
    58b2:	00 00                	add    %al,(%rax)
    58b4:	00 00                	add    %al,(%rax)
    58b6:	00 00                	add    %al,(%rax)
    58b8:	46 05 00 00 00 00    	rex.RX add $0x0,%eax
    58be:	00 00                	add    %al,(%rax)
    58c0:	0e                   	(bad)
    58c1:	00 00                	add    %al,(%rax)
    58c3:	00 00                	add    %al,(%rax)
    58c5:	00 00                	add    %al,(%rax)
    58c7:	00 06                	add    %al,(%rsi)
    58c9:	00 00                	add    %al,(%rax)
    58cb:	00 00                	add    %al,(%rax)
    58cd:	00 00                	add    %al,(%rax)
    58cf:	00 02                	add    %al,(%rdx)
    58d1:	00 00                	add    %al,(%rax)
    58d3:	00 00                	add    %al,(%rax)
    58d5:	00 00                	add    %al,(%rax)
    58d7:	00 02                	add    %al,(%rdx)
    58d9:	00 00                	add    %al,(%rax)
    58db:	00 00                	add    %al,(%rax)
    58dd:	00 00                	add    %al,(%rax)
    58df:	00 7e 00             	add    %bh,0x0(%rsi)
    58e2:	00 00                	add    %al,(%rax)
    58e4:	fe                   	(bad)
    58e5:	ff                   	(bad)
    58e6:	ff 6f 02             	ljmp   *0x2(%rdi)
    58e9:	00 00                	add    %al,(%rax)
    58eb:	00 00                	add    %al,(%rax)
    58ed:	00 00                	add    %al,(%rax)
    58ef:	00 58 05             	add    %bl,0x5(%rax)
    58f2:	00 00                	add    %al,(%rax)
    58f4:	00 00                	add    %al,(%rax)
    58f6:	00 00                	add    %al,(%rax)
    58f8:	58                   	pop    %rax
    58f9:	05 00 00 00 00       	add    $0x0,%eax
    58fe:	00 00                	add    %al,(%rax)
    5900:	30 00                	xor    %al,(%rax)
    5902:	00 00                	add    %al,(%rax)
    5904:	00 00                	add    %al,(%rax)
    5906:	00 00                	add    %al,(%rax)
    5908:	07                   	(bad)
    5909:	00 00                	add    %al,(%rax)
    590b:	00 01                	add    %al,(%rcx)
    590d:	00 00                	add    %al,(%rax)
    590f:	00 08                	add    %cl,(%rax)
	...
    591d:	00 00                	add    %al,(%rax)
    591f:	00 8d 00 00 00 04    	add    %cl,0x4000000(%rbp)
    5925:	00 00                	add    %al,(%rax)
    5927:	00 02                	add    %al,(%rdx)
    5929:	00 00                	add    %al,(%rax)
    592b:	00 00                	add    %al,(%rax)
    592d:	00 00                	add    %al,(%rax)
    592f:	00 88 05 00 00 00    	add    %cl,0x5(%rax)
    5935:	00 00                	add    %al,(%rax)
    5937:	00 88 05 00 00 00    	add    %cl,0x5(%rax)
    593d:	00 00                	add    %al,(%rax)
    593f:	00 c0                	add    %al,%al
    5941:	00 00                	add    %al,(%rax)
    5943:	00 00                	add    %al,(%rax)
    5945:	00 00                	add    %al,(%rax)
    5947:	00 06                	add    %al,(%rsi)
    5949:	00 00                	add    %al,(%rax)
    594b:	00 00                	add    %al,(%rax)
    594d:	00 00                	add    %al,(%rax)
    594f:	00 08                	add    %cl,(%rax)
    5951:	00 00                	add    %al,(%rax)
    5953:	00 00                	add    %al,(%rax)
    5955:	00 00                	add    %al,(%rax)
    5957:	00 18                	add    %bl,(%rax)
    5959:	00 00                	add    %al,(%rax)
    595b:	00 00                	add    %al,(%rax)
    595d:	00 00                	add    %al,(%rax)
    595f:	00 97 00 00 00 04    	add    %dl,0x4000000(%rdi)
    5965:	00 00                	add    %al,(%rax)
    5967:	00 42 00             	add    %al,0x0(%rdx)
    596a:	00 00                	add    %al,(%rax)
    596c:	00 00                	add    %al,(%rax)
    596e:	00 00                	add    %al,(%rax)
    5970:	48 06                	rex.W (bad)
    5972:	00 00                	add    %al,(%rax)
    5974:	00 00                	add    %al,(%rax)
    5976:	00 00                	add    %al,(%rax)
    5978:	48 06                	rex.W (bad)
    597a:	00 00                	add    %al,(%rax)
    597c:	00 00                	add    %al,(%rax)
    597e:	00 00                	add    %al,(%rax)
    5980:	18 00                	sbb    %al,(%rax)
    5982:	00 00                	add    %al,(%rax)
    5984:	00 00                	add    %al,(%rax)
    5986:	00 00                	add    %al,(%rax)
    5988:	06                   	(bad)
    5989:	00 00                	add    %al,(%rax)
    598b:	00 18                	add    %bl,(%rax)
    598d:	00 00                	add    %al,(%rax)
    598f:	00 08                	add    %cl,(%rax)
    5991:	00 00                	add    %al,(%rax)
    5993:	00 00                	add    %al,(%rax)
    5995:	00 00                	add    %al,(%rax)
    5997:	00 18                	add    %bl,(%rax)
    5999:	00 00                	add    %al,(%rax)
    599b:	00 00                	add    %al,(%rax)
    599d:	00 00                	add    %al,(%rax)
    599f:	00 a1 00 00 00 01    	add    %ah,0x1000000(%rcx)
    59a5:	00 00                	add    %al,(%rax)
    59a7:	00 06                	add    %al,(%rsi)
	...
    59b1:	10 00                	adc    %al,(%rax)
    59b3:	00 00                	add    %al,(%rax)
    59b5:	00 00                	add    %al,(%rax)
    59b7:	00 00                	add    %al,(%rax)
    59b9:	10 00                	adc    %al,(%rax)
    59bb:	00 00                	add    %al,(%rax)
    59bd:	00 00                	add    %al,(%rax)
    59bf:	00 1b                	add    %bl,(%rbx)
	...
    59cd:	00 00                	add    %al,(%rax)
    59cf:	00 04 00             	add    %al,(%rax,%rax,1)
	...
    59de:	00 00                	add    %al,(%rax)
    59e0:	9c                   	pushf
    59e1:	00 00                	add    %al,(%rax)
    59e3:	00 01                	add    %al,(%rcx)
    59e5:	00 00                	add    %al,(%rax)
    59e7:	00 06                	add    %al,(%rsi)
    59e9:	00 00                	add    %al,(%rax)
    59eb:	00 00                	add    %al,(%rax)
    59ed:	00 00                	add    %al,(%rax)
    59ef:	00 20                	add    %ah,(%rax)
    59f1:	10 00                	adc    %al,(%rax)
    59f3:	00 00                	add    %al,(%rax)
    59f5:	00 00                	add    %al,(%rax)
    59f7:	00 20                	add    %ah,(%rax)
    59f9:	10 00                	adc    %al,(%rax)
    59fb:	00 00                	add    %al,(%rax)
    59fd:	00 00                	add    %al,(%rax)
    59ff:	00 20                	add    %ah,(%rax)
	...
    5a0d:	00 00                	add    %al,(%rax)
    5a0f:	00 10                	add    %dl,(%rax)
    5a11:	00 00                	add    %al,(%rax)
    5a13:	00 00                	add    %al,(%rax)
    5a15:	00 00                	add    %al,(%rax)
    5a17:	00 10                	add    %dl,(%rax)
    5a19:	00 00                	add    %al,(%rax)
    5a1b:	00 00                	add    %al,(%rax)
    5a1d:	00 00                	add    %al,(%rax)
    5a1f:	00 a7 00 00 00 01    	add    %ah,0x1000000(%rdi)
    5a25:	00 00                	add    %al,(%rax)
    5a27:	00 06                	add    %al,(%rsi)
    5a29:	00 00                	add    %al,(%rax)
    5a2b:	00 00                	add    %al,(%rax)
    5a2d:	00 00                	add    %al,(%rax)
    5a2f:	00 40 10             	add    %al,0x10(%rax)
    5a32:	00 00                	add    %al,(%rax)
    5a34:	00 00                	add    %al,(%rax)
    5a36:	00 00                	add    %al,(%rax)
    5a38:	40 10 00             	rex adc %al,(%rax)
    5a3b:	00 00                	add    %al,(%rax)
    5a3d:	00 00                	add    %al,(%rax)
    5a3f:	00 10                	add    %dl,(%rax)
	...
    5a4d:	00 00                	add    %al,(%rax)
    5a4f:	00 10                	add    %dl,(%rax)
    5a51:	00 00                	add    %al,(%rax)
    5a53:	00 00                	add    %al,(%rax)
    5a55:	00 00                	add    %al,(%rax)
    5a57:	00 10                	add    %dl,(%rax)
    5a59:	00 00                	add    %al,(%rax)
    5a5b:	00 00                	add    %al,(%rax)
    5a5d:	00 00                	add    %al,(%rax)
    5a5f:	00 b0 00 00 00 01    	add    %dh,0x1000000(%rax)
    5a65:	00 00                	add    %al,(%rax)
    5a67:	00 06                	add    %al,(%rsi)
    5a69:	00 00                	add    %al,(%rax)
    5a6b:	00 00                	add    %al,(%rax)
    5a6d:	00 00                	add    %al,(%rax)
    5a6f:	00 50 10             	add    %dl,0x10(%rax)
    5a72:	00 00                	add    %al,(%rax)
    5a74:	00 00                	add    %al,(%rax)
    5a76:	00 00                	add    %al,(%rax)
    5a78:	50                   	push   %rax
    5a79:	10 00                	adc    %al,(%rax)
    5a7b:	00 00                	add    %al,(%rax)
    5a7d:	00 00                	add    %al,(%rax)
    5a7f:	00 10                	add    %dl,(%rax)
	...
    5a8d:	00 00                	add    %al,(%rax)
    5a8f:	00 10                	add    %dl,(%rax)
    5a91:	00 00                	add    %al,(%rax)
    5a93:	00 00                	add    %al,(%rax)
    5a95:	00 00                	add    %al,(%rax)
    5a97:	00 10                	add    %dl,(%rax)
    5a99:	00 00                	add    %al,(%rax)
    5a9b:	00 00                	add    %al,(%rax)
    5a9d:	00 00                	add    %al,(%rax)
    5a9f:	00 b9 00 00 00 01    	add    %bh,0x1000000(%rcx)
    5aa5:	00 00                	add    %al,(%rax)
    5aa7:	00 06                	add    %al,(%rsi)
    5aa9:	00 00                	add    %al,(%rax)
    5aab:	00 00                	add    %al,(%rax)
    5aad:	00 00                	add    %al,(%rax)
    5aaf:	00 60 10             	add    %ah,0x10(%rax)
    5ab2:	00 00                	add    %al,(%rax)
    5ab4:	00 00                	add    %al,(%rax)
    5ab6:	00 00                	add    %al,(%rax)
    5ab8:	60                   	(bad)
    5ab9:	10 00                	adc    %al,(%rax)
    5abb:	00 00                	add    %al,(%rax)
    5abd:	00 00                	add    %al,(%rax)
    5abf:	00 07                	add    %al,(%rdi)
    5ac1:	01 00                	add    %eax,(%rax)
	...
    5acf:	00 10                	add    %dl,(%rax)
	...
    5add:	00 00                	add    %al,(%rax)
    5adf:	00 bf 00 00 00 01    	add    %bh,0x1000000(%rdi)
    5ae5:	00 00                	add    %al,(%rax)
    5ae7:	00 06                	add    %al,(%rsi)
    5ae9:	00 00                	add    %al,(%rax)
    5aeb:	00 00                	add    %al,(%rax)
    5aed:	00 00                	add    %al,(%rax)
    5aef:	00 68 11             	add    %ch,0x11(%rax)
    5af2:	00 00                	add    %al,(%rax)
    5af4:	00 00                	add    %al,(%rax)
    5af6:	00 00                	add    %al,(%rax)
    5af8:	68 11 00 00 00       	push   $0x11
    5afd:	00 00                	add    %al,(%rax)
    5aff:	00 0d 00 00 00 00    	add    %cl,0x0(%rip)        # 5b05 <_end+0x1aed>
	...
    5b0d:	00 00                	add    %al,(%rax)
    5b0f:	00 04 00             	add    %al,(%rax,%rax,1)
	...
    5b1e:	00 00                	add    %al,(%rax)
    5b20:	c5 00 00             	(bad)
    5b23:	00 01                	add    %al,(%rcx)
    5b25:	00 00                	add    %al,(%rax)
    5b27:	00 02                	add    %al,(%rdx)
	...
    5b31:	20 00                	and    %al,(%rax)
    5b33:	00 00                	add    %al,(%rax)
    5b35:	00 00                	add    %al,(%rax)
    5b37:	00 00                	add    %al,(%rax)
    5b39:	20 00                	and    %al,(%rax)
    5b3b:	00 00                	add    %al,(%rax)
    5b3d:	00 00                	add    %al,(%rax)
    5b3f:	00 12                	add    %dl,(%rdx)
	...
    5b4d:	00 00                	add    %al,(%rax)
    5b4f:	00 04 00             	add    %al,(%rax,%rax,1)
	...
    5b5e:	00 00                	add    %al,(%rax)
    5b60:	cd 00                	int    $0x0
    5b62:	00 00                	add    %al,(%rax)
    5b64:	01 00                	add    %eax,(%rax)
    5b66:	00 00                	add    %al,(%rax)
    5b68:	02 00                	add    (%rax),%al
    5b6a:	00 00                	add    %al,(%rax)
    5b6c:	00 00                	add    %al,(%rax)
    5b6e:	00 00                	add    %al,(%rax)
    5b70:	14 20                	adc    $0x20,%al
    5b72:	00 00                	add    %al,(%rax)
    5b74:	00 00                	add    %al,(%rax)
    5b76:	00 00                	add    %al,(%rax)
    5b78:	14 20                	adc    $0x20,%al
    5b7a:	00 00                	add    %al,(%rax)
    5b7c:	00 00                	add    %al,(%rax)
    5b7e:	00 00                	add    %al,(%rax)
    5b80:	34 00                	xor    $0x0,%al
	...
    5b8e:	00 00                	add    %al,(%rax)
    5b90:	04 00                	add    $0x0,%al
	...
    5b9e:	00 00                	add    %al,(%rax)
    5ba0:	db 00                	fildl  (%rax)
    5ba2:	00 00                	add    %al,(%rax)
    5ba4:	01 00                	add    %eax,(%rax)
    5ba6:	00 00                	add    %al,(%rax)
    5ba8:	02 00                	add    (%rax),%al
    5baa:	00 00                	add    %al,(%rax)
    5bac:	00 00                	add    %al,(%rax)
    5bae:	00 00                	add    %al,(%rax)
    5bb0:	48 20 00             	rex.W and %al,(%rax)
    5bb3:	00 00                	add    %al,(%rax)
    5bb5:	00 00                	add    %al,(%rax)
    5bb7:	00 48 20             	add    %cl,0x20(%rax)
    5bba:	00 00                	add    %al,(%rax)
    5bbc:	00 00                	add    %al,(%rax)
    5bbe:	00 00                	add    %al,(%rax)
    5bc0:	ac                   	lods   %ds:(%rsi),%al
	...
    5bcd:	00 00                	add    %al,(%rax)
    5bcf:	00 08                	add    %cl,(%rax)
	...
    5bdd:	00 00                	add    %al,(%rax)
    5bdf:	00 e5                	add    %ah,%ch
    5be1:	00 00                	add    %al,(%rax)
    5be3:	00 0e                	add    %cl,(%rsi)
    5be5:	00 00                	add    %al,(%rax)
    5be7:	00 03                	add    %al,(%rbx)
    5be9:	00 00                	add    %al,(%rax)
    5beb:	00 00                	add    %al,(%rax)
    5bed:	00 00                	add    %al,(%rax)
    5bef:	00 b8 3d 00 00 00    	add    %bh,0x3d(%rax)
    5bf5:	00 00                	add    %al,(%rax)
    5bf7:	00 b8 2d 00 00 00    	add    %bh,0x2d(%rax)
    5bfd:	00 00                	add    %al,(%rax)
    5bff:	00 08                	add    %cl,(%rax)
	...
    5c0d:	00 00                	add    %al,(%rax)
    5c0f:	00 08                	add    %cl,(%rax)
    5c11:	00 00                	add    %al,(%rax)
    5c13:	00 00                	add    %al,(%rax)
    5c15:	00 00                	add    %al,(%rax)
    5c17:	00 08                	add    %cl,(%rax)
    5c19:	00 00                	add    %al,(%rax)
    5c1b:	00 00                	add    %al,(%rax)
    5c1d:	00 00                	add    %al,(%rax)
    5c1f:	00 f1                	add    %dh,%cl
    5c21:	00 00                	add    %al,(%rax)
    5c23:	00 0f                	add    %cl,(%rdi)
    5c25:	00 00                	add    %al,(%rax)
    5c27:	00 03                	add    %al,(%rbx)
    5c29:	00 00                	add    %al,(%rax)
    5c2b:	00 00                	add    %al,(%rax)
    5c2d:	00 00                	add    %al,(%rax)
    5c2f:	00 c0                	add    %al,%al
    5c31:	3d 00 00 00 00       	cmp    $0x0,%eax
    5c36:	00 00                	add    %al,(%rax)
    5c38:	c0 2d 00 00 00 00 00 	shrb   $0x0,0x0(%rip)        # 5c3f <_end+0x1c27>
    5c3f:	00 08                	add    %cl,(%rax)
	...
    5c4d:	00 00                	add    %al,(%rax)
    5c4f:	00 08                	add    %cl,(%rax)
    5c51:	00 00                	add    %al,(%rax)
    5c53:	00 00                	add    %al,(%rax)
    5c55:	00 00                	add    %al,(%rax)
    5c57:	00 08                	add    %cl,(%rax)
    5c59:	00 00                	add    %al,(%rax)
    5c5b:	00 00                	add    %al,(%rax)
    5c5d:	00 00                	add    %al,(%rax)
    5c5f:	00 fd                	add    %bh,%ch
    5c61:	00 00                	add    %al,(%rax)
    5c63:	00 06                	add    %al,(%rsi)
    5c65:	00 00                	add    %al,(%rax)
    5c67:	00 03                	add    %al,(%rbx)
    5c69:	00 00                	add    %al,(%rax)
    5c6b:	00 00                	add    %al,(%rax)
    5c6d:	00 00                	add    %al,(%rax)
    5c6f:	00 c8                	add    %cl,%al
    5c71:	3d 00 00 00 00       	cmp    $0x0,%eax
    5c76:	00 00                	add    %al,(%rax)
    5c78:	c8 2d 00 00          	enter  $0x2d,$0x0
    5c7c:	00 00                	add    %al,(%rax)
    5c7e:	00 00                	add    %al,(%rax)
    5c80:	f0 01 00             	lock add %eax,(%rax)
    5c83:	00 00                	add    %al,(%rax)
    5c85:	00 00                	add    %al,(%rax)
    5c87:	00 07                	add    %al,(%rdi)
    5c89:	00 00                	add    %al,(%rax)
    5c8b:	00 00                	add    %al,(%rax)
    5c8d:	00 00                	add    %al,(%rax)
    5c8f:	00 08                	add    %cl,(%rax)
    5c91:	00 00                	add    %al,(%rax)
    5c93:	00 00                	add    %al,(%rax)
    5c95:	00 00                	add    %al,(%rax)
    5c97:	00 10                	add    %dl,(%rax)
    5c99:	00 00                	add    %al,(%rax)
    5c9b:	00 00                	add    %al,(%rax)
    5c9d:	00 00                	add    %al,(%rax)
    5c9f:	00 ab 00 00 00 01    	add    %ch,0x1000000(%rbx)
    5ca5:	00 00                	add    %al,(%rax)
    5ca7:	00 03                	add    %al,(%rbx)
    5ca9:	00 00                	add    %al,(%rax)
    5cab:	00 00                	add    %al,(%rax)
    5cad:	00 00                	add    %al,(%rax)
    5caf:	00 b8 3f 00 00 00    	add    %bh,0x3f(%rax)
    5cb5:	00 00                	add    %al,(%rax)
    5cb7:	00 b8 2f 00 00 00    	add    %bh,0x2f(%rax)
    5cbd:	00 00                	add    %al,(%rax)
    5cbf:	00 48 00             	add    %cl,0x0(%rax)
	...
    5cce:	00 00                	add    %al,(%rax)
    5cd0:	08 00                	or     %al,(%rax)
    5cd2:	00 00                	add    %al,(%rax)
    5cd4:	00 00                	add    %al,(%rax)
    5cd6:	00 00                	add    %al,(%rax)
    5cd8:	08 00                	or     %al,(%rax)
    5cda:	00 00                	add    %al,(%rax)
    5cdc:	00 00                	add    %al,(%rax)
    5cde:	00 00                	add    %al,(%rax)
    5ce0:	06                   	(bad)
    5ce1:	01 00                	add    %eax,(%rax)
    5ce3:	00 01                	add    %al,(%rcx)
    5ce5:	00 00                	add    %al,(%rax)
    5ce7:	00 03                	add    %al,(%rbx)
	...
    5cf1:	40 00 00             	rex add %al,(%rax)
    5cf4:	00 00                	add    %al,(%rax)
    5cf6:	00 00                	add    %al,(%rax)
    5cf8:	00 30                	add    %dh,(%rax)
    5cfa:	00 00                	add    %al,(%rax)
    5cfc:	00 00                	add    %al,(%rax)
    5cfe:	00 00                	add    %al,(%rax)
    5d00:	10 00                	adc    %al,(%rax)
	...
    5d0e:	00 00                	add    %al,(%rax)
    5d10:	08 00                	or     %al,(%rax)
	...
    5d1e:	00 00                	add    %al,(%rax)
    5d20:	0c 01                	or     $0x1,%al
    5d22:	00 00                	add    %al,(%rax)
    5d24:	08 00                	or     %al,(%rax)
    5d26:	00 00                	add    %al,(%rax)
    5d28:	03 00                	add    (%rax),%eax
    5d2a:	00 00                	add    %al,(%rax)
    5d2c:	00 00                	add    %al,(%rax)
    5d2e:	00 00                	add    %al,(%rax)
    5d30:	10 40 00             	adc    %al,0x0(%rax)
    5d33:	00 00                	add    %al,(%rax)
    5d35:	00 00                	add    %al,(%rax)
    5d37:	00 10                	add    %dl,(%rax)
    5d39:	30 00                	xor    %al,(%rax)
    5d3b:	00 00                	add    %al,(%rax)
    5d3d:	00 00                	add    %al,(%rax)
    5d3f:	00 08                	add    %cl,(%rax)
	...
    5d4d:	00 00                	add    %al,(%rax)
    5d4f:	00 01                	add    %al,(%rcx)
	...
    5d5d:	00 00                	add    %al,(%rax)
    5d5f:	00 11                	add    %dl,(%rcx)
    5d61:	01 00                	add    %eax,(%rax)
    5d63:	00 01                	add    %al,(%rcx)
    5d65:	00 00                	add    %al,(%rax)
    5d67:	00 30                	add    %dh,(%rax)
	...
    5d75:	00 00                	add    %al,(%rax)
    5d77:	00 10                	add    %dl,(%rax)
    5d79:	30 00                	xor    %al,(%rax)
    5d7b:	00 00                	add    %al,(%rax)
    5d7d:	00 00                	add    %al,(%rax)
    5d7f:	00 2b                	add    %ch,(%rbx)
	...
    5d8d:	00 00                	add    %al,(%rax)
    5d8f:	00 01                	add    %al,(%rcx)
    5d91:	00 00                	add    %al,(%rax)
    5d93:	00 00                	add    %al,(%rax)
    5d95:	00 00                	add    %al,(%rax)
    5d97:	00 01                	add    %al,(%rcx)
    5d99:	00 00                	add    %al,(%rax)
    5d9b:	00 00                	add    %al,(%rax)
    5d9d:	00 00                	add    %al,(%rax)
    5d9f:	00 01                	add    %al,(%rcx)
    5da1:	00 00                	add    %al,(%rax)
    5da3:	00 02                	add    %al,(%rdx)
	...
    5db5:	00 00                	add    %al,(%rax)
    5db7:	00 40 30             	add    %al,0x30(%rax)
    5dba:	00 00                	add    %al,(%rax)
    5dbc:	00 00                	add    %al,(%rax)
    5dbe:	00 00                	add    %al,(%rax)
    5dc0:	60                   	(bad)
    5dc1:	03 00                	add    (%rax),%eax
    5dc3:	00 00                	add    %al,(%rax)
    5dc5:	00 00                	add    %al,(%rax)
    5dc7:	00 1d 00 00 00 12    	add    %bl,0x12000000(%rip)        # 12005dcd <_end+0x12001db5>
    5dcd:	00 00                	add    %al,(%rax)
    5dcf:	00 08                	add    %cl,(%rax)
    5dd1:	00 00                	add    %al,(%rax)
    5dd3:	00 00                	add    %al,(%rax)
    5dd5:	00 00                	add    %al,(%rax)
    5dd7:	00 18                	add    %bl,(%rax)
    5dd9:	00 00                	add    %al,(%rax)
    5ddb:	00 00                	add    %al,(%rax)
    5ddd:	00 00                	add    %al,(%rax)
    5ddf:	00 09                	add    %cl,(%rcx)
    5de1:	00 00                	add    %al,(%rax)
    5de3:	00 03                	add    %al,(%rbx)
	...
    5df5:	00 00                	add    %al,(%rax)
    5df7:	00 a0 33 00 00 00    	add    %ah,0x33(%rax)
    5dfd:	00 00                	add    %al,(%rax)
    5dff:	00 db                	add    %bl,%bl
    5e01:	01 00                	add    %eax,(%rax)
	...
    5e0f:	00 01                	add    %al,(%rcx)
	...
    5e1d:	00 00                	add    %al,(%rax)
    5e1f:	00 11                	add    %dl,(%rcx)
    5e21:	00 00                	add    %al,(%rax)
    5e23:	00 03                	add    %al,(%rbx)
	...
    5e35:	00 00                	add    %al,(%rax)
    5e37:	00 7b 35             	add    %bh,0x35(%rbx)
    5e3a:	00 00                	add    %al,(%rax)
    5e3c:	00 00                	add    %al,(%rax)
    5e3e:	00 00                	add    %al,(%rax)
    5e40:	21 01                	and    %eax,(%rcx)
	...
    5e4e:	00 00                	add    %al,(%rax)
    5e50:	01 00                	add    %eax,(%rax)
	...
    5e5e:	00 00                	add    %al,(%rax)
    5e60:	1a 01                	sbb    (%rcx),%al
    5e62:	00 00                	add    %al,(%rax)
    5e64:	01 00                	add    %eax,(%rax)
    5e66:	00 00                	add    %al,(%rax)
    5e68:	06                   	(bad)
    5e69:	00 00                	add    %al,(%rax)
    5e6b:	00 00                	add    %al,(%rax)
    5e6d:	00 00                	add    %al,(%rax)
    5e6f:	00 a0 56 00 00 00    	add    %ah,0x56(%rax)
    5e75:	00 00                	add    %al,(%rax)
    5e77:	00 a0 36 00 00 00    	add    %ah,0x36(%rax)
    5e7d:	00 00                	add    %al,(%rax)
    5e7f:	00 00                	add    %al,(%rax)
    5e81:	10 00                	adc    %al,(%rax)
	...
    5e8f:	00 10                	add    %dl,(%rax)
	...
