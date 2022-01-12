package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func buildIngress(opts ...func(*networking.Ingress)) *networking.Ingress {
	i := &networking.Ingress{}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

func iNamespace(value string) func(*networking.Ingress) {
	return func(i *networking.Ingress) {
		i.Namespace = value
	}
}

func iAnnotation(name string, value string) func(*networking.Ingress) {
	return func(i *networking.Ingress) {
		if i.Annotations == nil {
			i.Annotations = make(map[string]string)
		}
		i.Annotations[name] = value
	}
}

func iRules(opts ...func(*networking.IngressSpec)) func(*networking.Ingress) {
	return func(i *networking.Ingress) {
		s := &networking.IngressSpec{}
		for _, opt := range opts {
			opt(s)
		}
		i.Spec = *s
	}
}

func iSpecBackends(opts ...func(*networking.IngressSpec)) func(*networking.Ingress) {
	return func(i *networking.Ingress) {
		s := &networking.IngressSpec{}
		for _, opt := range opts {
			opt(s)
		}
		i.Spec = *s
	}
}

func iSpecBackend(opts ...func(*networking.IngressBackend)) func(*networking.IngressSpec) {
	return func(s *networking.IngressSpec) {
		p := &networking.IngressBackend{}
		for _, opt := range opts {
			opt(p)
		}
		s.DefaultBackend = p
	}
}

func iIngressBackend(name string, port intstr.IntOrString) func(*networking.IngressBackend) {
	return func(p *networking.IngressBackend) {
		var bePort networking.ServiceBackendPort

		if port.Type == intstr.Int {
			bePort = networking.ServiceBackendPort{
				Number: port.IntVal,
			}
		} else {
			bePort = networking.ServiceBackendPort{
				Name: port.StrVal,
			}
		}

		be := &networking.IngressServiceBackend{
			Name: name,
			Port: bePort,
		}

		p.Service = be
	}
}

func iRule(opts ...func(*networking.IngressRule)) func(*networking.IngressSpec) {
	return func(spec *networking.IngressSpec) {
		r := &networking.IngressRule{}
		for _, opt := range opts {
			opt(r)
		}
		spec.Rules = append(spec.Rules, *r)
	}
}

func iHost(name string) func(*networking.IngressRule) {
	return func(rule *networking.IngressRule) {
		rule.Host = name
	}
}

func iPaths(opts ...func(*networking.HTTPIngressRuleValue)) func(*networking.IngressRule) {
	return func(rule *networking.IngressRule) {
		rule.HTTP = &networking.HTTPIngressRuleValue{}
		for _, opt := range opts {
			opt(rule.HTTP)
		}
	}
}

func onePath(opts ...func(*networking.HTTPIngressPath)) func(*networking.HTTPIngressRuleValue) {
	return func(irv *networking.HTTPIngressRuleValue) {
		p := &networking.HTTPIngressPath{}
		for _, opt := range opts {
			opt(p)
		}
		irv.Paths = append(irv.Paths, *p)
	}
}

func iPath(name string) func(*networking.HTTPIngressPath) {
	return func(p *networking.HTTPIngressPath) {
		p.Path = name
	}
}

func iBackend(name string, port intstr.IntOrString) func(*networking.HTTPIngressPath) {
	return func(p *networking.HTTPIngressPath) {
		var bePort networking.ServiceBackendPort

		if port.Type == intstr.Int {
			bePort = networking.ServiceBackendPort{
				Number: port.IntVal,
			}
		} else {
			bePort = networking.ServiceBackendPort{
				Name: port.StrVal,
			}
		}

		be := &networking.IngressServiceBackend{
			Name: name,
			Port: bePort,
		}

		p.Backend = networking.IngressBackend{
			Service: be,
		}
	}
}

func iTLSes(opts ...func(*networking.IngressTLS)) func(*networking.Ingress) {
	return func(i *networking.Ingress) {
		for _, opt := range opts {
			iTLS := networking.IngressTLS{}
			opt(&iTLS)
			i.Spec.TLS = append(i.Spec.TLS, iTLS)
		}
	}
}

func iTLS(secret string, hosts ...string) func(*networking.IngressTLS) {
	return func(i *networking.IngressTLS) {
		i.SecretName = secret
		i.Hosts = hosts
	}
}

// Test

func TestBuildIngress(t *testing.T) {
	i := buildIngress(
		iNamespace("testing"),
		iRules(
			iRule(iHost("foo"), iPaths(
				onePath(iPath("/bar"), iBackend("service1", intstr.FromInt(80))),
				onePath(iPath("/namedthing"), iBackend("service4", intstr.FromString("https")))),
			),
			iRule(iHost("bar"), iPaths(
				onePath(iBackend("service3", intstr.FromString("https"))),
				onePath(iBackend("service2", intstr.FromInt(802))),
			),
			),
		),
		iTLSes(
			iTLS("tls-secret", "foo"),
		),
	)

	assert.EqualValues(t, sampleIngress(), i)
}

func sampleIngress() *networking.Ingress {
	return &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testing",
		},
		Spec: networking.IngressSpec{
			Rules: []networking.IngressRule{
				{
					Host: "foo",
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: []networking.HTTPIngressPath{
								{
									Path: "/bar",
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "service1",
											Port: networking.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
								{
									Path: "/namedthing",
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "service4",
											Port: networking.ServiceBackendPort{
												Name: "https",
											},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "bar",
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: []networking.HTTPIngressPath{
								{
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "service3",
											Port: networking.ServiceBackendPort{
												Name: "https",
											},
										},
									},
								},
								{
									Backend: networking.IngressBackend{
										Service: &networking.IngressServiceBackend{
											Name: "service2",
											Port: networking.ServiceBackendPort{
												Number: 802,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			TLS: []networking.IngressTLS{
				{
					Hosts:      []string{"foo"},
					SecretName: "tls-secret",
				},
			},
		},
	}
}
