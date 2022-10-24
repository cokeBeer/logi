package wordlist

const (
	MAVEN_DICT     = "mvn"
	YSOSERIAL_DICT = "yso"
	JNDI_DICT      = "jndi"
)

var (
	Manager DictManager
	mvn     = []string{
		"android.support.annotation.AnimRes",
		"ch.qos.logback.core.Appender",
		"ch.qos.logbackic.AsyncAppender",
		"clojure.asm.CurrentFrame",
		"clojure.tools.nrepl.main",
		"com.fasterxml.jackson.annotation.JacksonAnnotation",
		"com.fasterxml.jackson.core.Base64Variant",
		"com.fasterxml.jackson.databind.AbstractTypeResolver",
		"com.google.common.annotations.Beta",
		"com.google.gson.JsonDeserializer",
		"com.google.inject.AbstractModule",
		"com.mysql.cj.AbstractPreparedQuery",
		"junit.textui.TestRunner",
		"kotlin.jvm.internal.TypeIntrinsics",
		"lombok.AccessLevel",
		"okhttp3.Dispatcher",
		"org.apache.commons.beanutils.FluentPropertyBeanIntrospector",
		"org.apache.commons.cli2.Argument",
		"org.apache.commons.codec.binary.Base32",
		"org.apache.commons.collections.ArrayStack",
		"org.apache.commons.io.comparator.DirectoryFileComparator",
		"org.apache.commons.lang3.SerializationException",
		"org.apache.commons.lang.ArrayUtils",
		"org.apache.commons.logging.impl.AvalonLogger",
		"org.apache.commons.logging.impl.NoOpLog",
		"org.apache.http.client.utils.URIBuilder",
		"org.apache.http.Consts",
		"org.apache.log4j.Appender",
		"org.apache.log4j.MDCFriend",
		"org.apache.logging.log4j.core.appender.AppenderLoggingException",
		"org.apache.logging.log4j.internal.DefaultLogBuilder",
		"org.apache.logging.slf4j.Log4jMDCAdapter",
		"org.apache.logging.slf4j.SLF4JLoggerContextFactory",
		"org.apache.maven.AbstractMavenLifecycleParticipant",
		"org.apache.maven.monitor.logging.DefaultLog",
		"org.apache.maven.plugins.annotations.InstantiationStrategy",
		"org.assertj.core.annotations.Beta",
		"org.codehaus.jackson.map.AbstractTypeResolver",
		"org.codehaus.plexus.util.LineOrientedInterpolatingReader",
		"org.easymock.EasyMockRule",
		"org.h2.Driver",
		"org.hamcrest.BaseDescription",
		"org.hamcrest.core.deprecated.HamcrestCoreIsDeprecated",
		"org.hamcrest.library.deprecated.HamcrestLibraryIsDeprecated",
		"org.joda.time.base.BaseSingleFieldPeriod",
		"org.json.CDL",
		"org.junit.jupiter.api.AfterAll",
		"org.junit.jupiter.engine.Constants",
		"org.mockito.Answers",
		"org.osgi.application.ApplicationContext",
		"org.osgi.dto.DTO",
		"org.powermock.modules.junit4.PowerMockRunnerDelegate",
		"org.renjin.graphics.graphics",
		"org.renjin.grDevices.Colors",
		"org.renjin.grid.grid",
		"org.renjin.methods.Table.RData",
		"org.renjin.splines.splines",
		"org.renjin.stats.nls.NlsModel",
		"org.renjin.tools.Md5",
		"org.renjin.utils.WriteTable",
		"org.scalacheck.Arbitrary",
		"org.scalatest.AbstractSuite",
		"org.slf4j.event.DefaultLoggingEvent",
		"org.slf4j.simple.OutputChoice",
		"org.springframework.beans.TypeMismatchException",
		"org.springframework.boot.autoconfigure.mongo.MongoClientFactory",
		"org.springframework.boot.configurationprocessor.fieldvalues.javac.Tree",
		"org.springframework.core.ReactiveTypeDescriptor",
		"org.springframework.http.StreamingHttpOutputMessage",
		"org.springframework.instrumentloading.ResourceOverridingShadowingClassLoader",
		"org.springframework.jdbc.config.EmbeddedDatabaseBeanDefinitionParser",
		"org.springframework.test.annotation.ProfileValueSource",
		"org.springframework.web.servlet.HandlerExecutionChain",
		"org.testng.annotations.AfterClass",
		"sbt.testing.TestWildcardSelector",
		"scala.AnyVal",
		"scala.scalajs.js.Any",
		"groovy.lang.Binding",
		"org.hibernate.validator.HibernateValidator",
	}
	yso = []string{
		"org.apache.commons.collections.functors.ChainedTransformer",
		"org.apache.commons.collections.ExtendedProperties$1",
		"org.apache.commons.collections4.functors.ChainedTransformer",
		"org.apache.commons.collections4.FluentIterable",
		"org.apache.commons.beanutils.MappedPropertyDescriptor$1",
		"org.apache.commons.beanutils.DynaBeanMapDecorator$MapEntry",
		"org.apache.commons.beanutils.BeanIntrospectionData",
		"com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
		"com.mchange.v2.c3p0.test.AlwaysFailDataSource",
		"org.aspectj.weaver.tools.cache.SimpleCache",
		"bsh.CollectionManager$1",
		"bsh.engine.BshScriptEngine",
		"bsh.collection.CollectionIterator$1",
		"org.codehaus.groovy.reflection.ClassInfo$ClassInfoSet",
		"groovy.lang.Tuple2",
		"org.codehaus.groovy.runtime.dgm$1170",
		"com.sun.org.apache.bcel.internal.util.ClassLoader",
		"com.sun.corba.se.impl.orbutil.ORBClassLoader",
		"javax.swing.plaf.metal.MetalFileChooserUI$DirectoryComboBoxModel$1",
		"sun.awt.X11.AwtGraphicsConfigData",
		"sun.awt.windows.WButtonPeer",
	}
	jndi = []string{
		"org.apache.naming.factory.BeanFactory",
		"javax.el.ELProcessor",
		"groovy.lang.GroovyShell",
		"groovy.lang.GroovyClassLoader",
		"org.yaml.snakeyaml.Yaml",
		"com.thoughtworks.xstream.XStream",
		"org.xmlpull.v1.XmlPullParserException",
		"org.xmlpull.mxp1.MXParser",
		"org.mvel2.sh.ShellSession",
		"com.sun.glass.utils.NativeLibLoader",
		"org.apache.catalina.UserDatabase",
		"org.apache.catalina.users.MemoryUserDatabaseFactory",
		"org.h2.Driver",
		"org.postgresql.Driver",
		"com.mysql.jdbc.Driver",
		"com.mysql.cj.jdbc.Driver",
		"com.mysql.fabric.jdbc.FabricMySQLDriver",
		"oracle.jdbc.driver.OracleDriver",
		"org.apache.tomcat.dbcp.dbcp.BasicDataSourceFactory",
		"org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory",
		"org.apache.commons.dbcp.BasicDataSourceFactory",
		"org.apache.commons.pool.KeyedObjectPoolFactory",
		"org.apache.commons.dbcp2.BasicDataSourceFactory",
		"org.apache.commons.pool2.PooledObjectFactory",
		"org.apache.tomcat.jdbc.pool.DataSourceFactory",
		"org.apache.juli.logging.LogFactory",
		"com.alibaba.druid.pool.DruidDataSourceFactory",
		"com.zaxxer.hikari.HikariJNDIFactory",
		"org.slf4j.LoggerFactory",
		"com.ibm.ws.client.applicationclient.ClientJ2CCFFactory",
		"com.ibm.ws.webservices.engine.client.ServiceFactory",
	}
)

type DictWrapper struct {
	l    int
	dict *[]string
	name string
}

type DictManager struct {
	dicts map[string]*DictWrapper
}

func (w *DictWrapper) Len() int {
	return w.l
}

func (w *DictWrapper) Name() string {
	return w.name
}

func (w *DictWrapper) Choose(i int) string {
	return (*w.dict)[i]
}

func (m *DictManager) Set(name string, dict []string) {
	m.dicts[name] = &DictWrapper{l: len(dict), dict: &dict, name: name}
}

func (m *DictManager) Get(name string) (*DictWrapper, bool) {
	if dict, ok := m.dicts[name]; ok {
		return dict, true
	}
	return nil, false
}

func init() {
	Manager.dicts = make(map[string]*DictWrapper)
	Manager.Set(MAVEN_DICT, mvn)
	Manager.Set(YSOSERIAL_DICT, yso)
	Manager.Set(JNDI_DICT, jndi)
}
