
assem_test:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 2f 00 00 	mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	callq  *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	retq   

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 92 2f 00 00    	pushq  0x2f92(%rip)        # 3fb8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 93 2f 00 00 	bnd jmpq *0x2f93(%rip)        # 3fc0 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	pushq  $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmpq 1020 <.plt>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	pushq  $0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmpq 1020 <.plt>
    104f:	90                   	nop

Disassembly of section .plt.got:

0000000000001050 <__cxa_finalize@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 9d 2f 00 00 	bnd jmpq *0x2f9d(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    105b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001060 <__stack_chk_fail@plt>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	f2 ff 25 5d 2f 00 00 	bnd jmpq *0x2f5d(%rip)        # 3fc8 <__stack_chk_fail@GLIBC_2.4>
    106b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001070 <printf@plt>:
    1070:	f3 0f 1e fa          	endbr64 
    1074:	f2 ff 25 55 2f 00 00 	bnd jmpq *0x2f55(%rip)        # 3fd0 <printf@GLIBC_2.2.5>
    107b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001080 <_start>:
    1080:	f3 0f 1e fa          	endbr64 
    1084:	31 ed                	xor    %ebp,%ebp
    1086:	49 89 d1             	mov    %rdx,%r9
    1089:	5e                   	pop    %rsi
    108a:	48 89 e2             	mov    %rsp,%rdx
    108d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1091:	50                   	push   %rax
    1092:	54                   	push   %rsp
    1093:	4c 8d 05 26 02 00 00 	lea    0x226(%rip),%r8        # 12c0 <__libc_csu_fini>
    109a:	48 8d 0d af 01 00 00 	lea    0x1af(%rip),%rcx        # 1250 <__libc_csu_init>
    10a1:	48 8d 3d 2f 01 00 00 	lea    0x12f(%rip),%rdi        # 11d7 <main>
    10a8:	ff 15 32 2f 00 00    	callq  *0x2f32(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    10ae:	f4                   	hlt    
    10af:	90                   	nop

00000000000010b0 <deregister_tm_clones>:
    10b0:	48 8d 3d 59 2f 00 00 	lea    0x2f59(%rip),%rdi        # 4010 <__TMC_END__>
    10b7:	48 8d 05 52 2f 00 00 	lea    0x2f52(%rip),%rax        # 4010 <__TMC_END__>
    10be:	48 39 f8             	cmp    %rdi,%rax
    10c1:	74 15                	je     10d8 <deregister_tm_clones+0x28>
    10c3:	48 8b 05 0e 2f 00 00 	mov    0x2f0e(%rip),%rax        # 3fd8 <_ITM_deregisterTMCloneTable>
    10ca:	48 85 c0             	test   %rax,%rax
    10cd:	74 09                	je     10d8 <deregister_tm_clones+0x28>
    10cf:	ff e0                	jmpq   *%rax
    10d1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10d8:	c3                   	retq   
    10d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010e0 <register_tm_clones>:
    10e0:	48 8d 3d 29 2f 00 00 	lea    0x2f29(%rip),%rdi        # 4010 <__TMC_END__>
    10e7:	48 8d 35 22 2f 00 00 	lea    0x2f22(%rip),%rsi        # 4010 <__TMC_END__>
    10ee:	48 29 fe             	sub    %rdi,%rsi
    10f1:	48 89 f0             	mov    %rsi,%rax
    10f4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10f8:	48 c1 f8 03          	sar    $0x3,%rax
    10fc:	48 01 c6             	add    %rax,%rsi
    10ff:	48 d1 fe             	sar    %rsi
    1102:	74 14                	je     1118 <register_tm_clones+0x38>
    1104:	48 8b 05 e5 2e 00 00 	mov    0x2ee5(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable>
    110b:	48 85 c0             	test   %rax,%rax
    110e:	74 08                	je     1118 <register_tm_clones+0x38>
    1110:	ff e0                	jmpq   *%rax
    1112:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1118:	c3                   	retq   
    1119:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001120 <__do_global_dtors_aux>:
    1120:	f3 0f 1e fa          	endbr64 
    1124:	80 3d e5 2e 00 00 00 	cmpb   $0x0,0x2ee5(%rip)        # 4010 <__TMC_END__>
    112b:	75 2b                	jne    1158 <__do_global_dtors_aux+0x38>
    112d:	55                   	push   %rbp
    112e:	48 83 3d c2 2e 00 00 	cmpq   $0x0,0x2ec2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1135:	00 
    1136:	48 89 e5             	mov    %rsp,%rbp
    1139:	74 0c                	je     1147 <__do_global_dtors_aux+0x27>
    113b:	48 8b 3d c6 2e 00 00 	mov    0x2ec6(%rip),%rdi        # 4008 <__dso_handle>
    1142:	e8 09 ff ff ff       	callq  1050 <__cxa_finalize@plt>
    1147:	e8 64 ff ff ff       	callq  10b0 <deregister_tm_clones>
    114c:	c6 05 bd 2e 00 00 01 	movb   $0x1,0x2ebd(%rip)        # 4010 <__TMC_END__>
    1153:	5d                   	pop    %rbp
    1154:	c3                   	retq   
    1155:	0f 1f 00             	nopl   (%rax)
    1158:	c3                   	retq   
    1159:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001160 <frame_dummy>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	e9 77 ff ff ff       	jmpq   10e0 <register_tm_clones>

0000000000001169 <test_b>:
    1169:	f3 0f 1e fa          	endbr64 
    116d:	55                   	push   %rbp
    116e:	48 89 e5             	mov    %rsp,%rbp
    1171:	48 83 ec 10          	sub    $0x10,%rsp
    1175:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1179:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    117d:	48 89 c6             	mov    %rax,%rsi
    1180:	48 8d 3d 7d 0e 00 00 	lea    0xe7d(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1187:	b8 00 00 00 00       	mov    $0x0,%eax
    118c:	e8 df fe ff ff       	callq  1070 <printf@plt>
    1191:	b8 f3 ff ff ff       	mov    $0xfffffff3,%eax
    1196:	c9                   	leaveq 
    1197:	c3                   	retq   

0000000000001198 <test_c>:
    1198:	f3 0f 1e fa          	endbr64 
    119c:	55                   	push   %rbp
    119d:	48 89 e5             	mov    %rsp,%rbp
    11a0:	48 83 ec 20          	sub    $0x20,%rsp
    11a4:	89 7d ec             	mov    %edi,-0x14(%rbp)
    11a7:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    11ab:	c7 45 f8 01 00 00 00 	movl   $0x1,-0x8(%rbp)
    11b2:	8b 55 f8             	mov    -0x8(%rbp),%edx
    11b5:	8b 45 ec             	mov    -0x14(%rbp),%eax
    11b8:	01 d0                	add    %edx,%eax
    11ba:	8d 50 0a             	lea    0xa(%rax),%edx
    11bd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    11c1:	89 10                	mov    %edx,(%rax)
    11c3:	48 8d 3d 45 0e 00 00 	lea    0xe45(%rip),%rdi        # 200f <_IO_stdin_used+0xf>
    11ca:	e8 9a ff ff ff       	callq  1169 <test_b>
    11cf:	89 45 fc             	mov    %eax,-0x4(%rbp)
    11d2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11d5:	c9                   	leaveq 
    11d6:	c3                   	retq   

00000000000011d7 <main>:
    11d7:	f3 0f 1e fa          	endbr64 
    11db:	55                   	push   %rbp
    11dc:	48 89 e5             	mov    %rsp,%rbp
    11df:	48 83 ec 20          	sub    $0x20,%rsp
    11e3:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    11ea:	00 00 
    11ec:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    11f0:	31 c0                	xor    %eax,%eax
    11f2:	c7 45 f0 08 00 00 00 	movl   $0x8,-0x10(%rbp)
    11f9:	c7 45 ec 09 00 00 00 	movl   $0x9,-0x14(%rbp)
    1200:	48 8d 55 ec          	lea    -0x14(%rbp),%rdx
    1204:	8b 45 f0             	mov    -0x10(%rbp),%eax
    1207:	48 89 d6             	mov    %rdx,%rsi
    120a:	89 c7                	mov    %eax,%edi
    120c:	e8 87 ff ff ff       	callq  1198 <test_c>
    1211:	89 45 f4             	mov    %eax,-0xc(%rbp)
    1214:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1217:	89 c6                	mov    %eax,%esi
    1219:	48 8d 3d fc 0d 00 00 	lea    0xdfc(%rip),%rdi        # 201c <_IO_stdin_used+0x1c>
    1220:	b8 00 00 00 00       	mov    $0x0,%eax
    1225:	e8 46 fe ff ff       	callq  1070 <printf@plt>
    122a:	b8 00 00 00 00       	mov    $0x0,%eax
    122f:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    1233:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    123a:	00 00 
    123c:	74 05                	je     1243 <main+0x6c>
    123e:	e8 1d fe ff ff       	callq  1060 <__stack_chk_fail@plt>
    1243:	c9                   	leaveq 
    1244:	c3                   	retq   
    1245:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    124c:	00 00 00 
    124f:	90                   	nop

0000000000001250 <__libc_csu_init>:
    1250:	f3 0f 1e fa          	endbr64 
    1254:	41 57                	push   %r15
    1256:	4c 8d 3d 53 2b 00 00 	lea    0x2b53(%rip),%r15        # 3db0 <__frame_dummy_init_array_entry>
    125d:	41 56                	push   %r14
    125f:	49 89 d6             	mov    %rdx,%r14
    1262:	41 55                	push   %r13
    1264:	49 89 f5             	mov    %rsi,%r13
    1267:	41 54                	push   %r12
    1269:	41 89 fc             	mov    %edi,%r12d
    126c:	55                   	push   %rbp
    126d:	48 8d 2d 44 2b 00 00 	lea    0x2b44(%rip),%rbp        # 3db8 <__do_global_dtors_aux_fini_array_entry>
    1274:	53                   	push   %rbx
    1275:	4c 29 fd             	sub    %r15,%rbp
    1278:	48 83 ec 08          	sub    $0x8,%rsp
    127c:	e8 7f fd ff ff       	callq  1000 <_init>
    1281:	48 c1 fd 03          	sar    $0x3,%rbp
    1285:	74 1f                	je     12a6 <__libc_csu_init+0x56>
    1287:	31 db                	xor    %ebx,%ebx
    1289:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1290:	4c 89 f2             	mov    %r14,%rdx
    1293:	4c 89 ee             	mov    %r13,%rsi
    1296:	44 89 e7             	mov    %r12d,%edi
    1299:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    129d:	48 83 c3 01          	add    $0x1,%rbx
    12a1:	48 39 dd             	cmp    %rbx,%rbp
    12a4:	75 ea                	jne    1290 <__libc_csu_init+0x40>
    12a6:	48 83 c4 08          	add    $0x8,%rsp
    12aa:	5b                   	pop    %rbx
    12ab:	5d                   	pop    %rbp
    12ac:	41 5c                	pop    %r12
    12ae:	41 5d                	pop    %r13
    12b0:	41 5e                	pop    %r14
    12b2:	41 5f                	pop    %r15
    12b4:	c3                   	retq   
    12b5:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    12bc:	00 00 00 00 

00000000000012c0 <__libc_csu_fini>:
    12c0:	f3 0f 1e fa          	endbr64 
    12c4:	c3                   	retq   

Disassembly of section .fini:

00000000000012c8 <_fini>:
    12c8:	f3 0f 1e fa          	endbr64 
    12cc:	48 83 ec 08          	sub    $0x8,%rsp
    12d0:	48 83 c4 08          	add    $0x8,%rsp
    12d4:	c3                   	retq   
