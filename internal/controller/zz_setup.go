// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/upjet/pkg/controller"

	rule "github.com/stakater/provider-cloudflare/internal/controller/access/rule"
	member "github.com/stakater/provider-cloudflare/internal/controller/account/member"
	subscription "github.com/stakater/provider-cloudflare/internal/controller/account/subscription"
	token "github.com/stakater/provider-cloudflare/internal/controller/account/token"
	shield "github.com/stakater/provider-cloudflare/internal/controller/api/shield"
	shielddiscoveryoperation "github.com/stakater/provider-cloudflare/internal/controller/api/shielddiscoveryoperation"
	shieldoperation "github.com/stakater/provider-cloudflare/internal/controller/api/shieldoperation"
	shieldoperationschemavalidationsettings "github.com/stakater/provider-cloudflare/internal/controller/api/shieldoperationschemavalidationsettings"
	shieldschema "github.com/stakater/provider-cloudflare/internal/controller/api/shieldschema"
	shieldschemavalidationsettings "github.com/stakater/provider-cloudflare/internal/controller/api/shieldschemavalidationsettings"
	tokenapi "github.com/stakater/provider-cloudflare/internal/controller/api/token"
	smartrouting "github.com/stakater/provider-cloudflare/internal/controller/argo/smartrouting"
	tieredcaching "github.com/stakater/provider-cloudflare/internal/controller/argo/tieredcaching"
	originpulls "github.com/stakater/provider-cloudflare/internal/controller/authenticated/originpulls"
	originpullscertificate "github.com/stakater/provider-cloudflare/internal/controller/authenticated/originpullscertificate"
	management "github.com/stakater/provider-cloudflare/internal/controller/bot/management"
	ipprefix "github.com/stakater/provider-cloudflare/internal/controller/byo/ipprefix"
	sfuapp "github.com/stakater/provider-cloudflare/internal/controller/calls/sfuapp"
	turnapp "github.com/stakater/provider-cloudflare/internal/controller/calls/turnapp"
	pack "github.com/stakater/provider-cloudflare/internal/controller/certificate/pack"
	connectorrules "github.com/stakater/provider-cloudflare/internal/controller/cloud/connectorrules"
	account "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/account"
	filter "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/filter"
	healthcheck "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/healthcheck"
	image "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/image"
	list "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/list"
	queue "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/queue"
	ruleset "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/ruleset"
	snippets "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/snippets"
	stream "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/stream"
	user "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/user"
	zone "github.com/stakater/provider-cloudflare/internal/controller/cloudflare/zone"
	onerequest "github.com/stakater/provider-cloudflare/internal/controller/cloudforce/onerequest"
	onerequestasset "github.com/stakater/provider-cloudflare/internal/controller/cloudforce/onerequestasset"
	onerequestmessage "github.com/stakater/provider-cloudflare/internal/controller/cloudforce/onerequestmessage"
	onerequestpriority "github.com/stakater/provider-cloudflare/internal/controller/cloudforce/onerequestpriority"
	scanningexpression "github.com/stakater/provider-cloudflare/internal/controller/content/scanningexpression"
	hostname "github.com/stakater/provider-cloudflare/internal/controller/custom/hostname"
	hostnamefallbackorigin "github.com/stakater/provider-cloudflare/internal/controller/custom/hostnamefallbackorigin"
	ssl "github.com/stakater/provider-cloudflare/internal/controller/custom/ssl"
	database "github.com/stakater/provider-cloudflare/internal/controller/d1/database"
	firewall "github.com/stakater/provider-cloudflare/internal/controller/dns/firewall"
	record "github.com/stakater/provider-cloudflare/internal/controller/dns/record"
	settings "github.com/stakater/provider-cloudflare/internal/controller/dns/settings"
	settingsinternalview "github.com/stakater/provider-cloudflare/internal/controller/dns/settingsinternalview"
	zonetransfersacl "github.com/stakater/provider-cloudflare/internal/controller/dns/zonetransfersacl"
	zonetransfersincoming "github.com/stakater/provider-cloudflare/internal/controller/dns/zonetransfersincoming"
	zonetransfersoutgoing "github.com/stakater/provider-cloudflare/internal/controller/dns/zonetransfersoutgoing"
	zonetransferspeer "github.com/stakater/provider-cloudflare/internal/controller/dns/zonetransferspeer"
	zonetransferstsig "github.com/stakater/provider-cloudflare/internal/controller/dns/zonetransferstsig"
	routingaddress "github.com/stakater/provider-cloudflare/internal/controller/email/routingaddress"
	routingcatchall "github.com/stakater/provider-cloudflare/internal/controller/email/routingcatchall"
	routingdns "github.com/stakater/provider-cloudflare/internal/controller/email/routingdns"
	routingrule "github.com/stakater/provider-cloudflare/internal/controller/email/routingrule"
	routingsettings "github.com/stakater/provider-cloudflare/internal/controller/email/routingsettings"
	securityblocksender "github.com/stakater/provider-cloudflare/internal/controller/email/securityblocksender"
	securityimpersonationregistry "github.com/stakater/provider-cloudflare/internal/controller/email/securityimpersonationregistry"
	securitytrusteddomains "github.com/stakater/provider-cloudflare/internal/controller/email/securitytrusteddomains"
	rulefirewall "github.com/stakater/provider-cloudflare/internal/controller/firewall/rule"
	tlssetting "github.com/stakater/provider-cloudflare/internal/controller/hostname/tlssetting"
	config "github.com/stakater/provider-cloudflare/internal/controller/hyperdrive/config"
	variant "github.com/stakater/provider-cloudflare/internal/controller/image/variant"
	certificate "github.com/stakater/provider-cloudflare/internal/controller/keyless/certificate"
	credentialcheck "github.com/stakater/provider-cloudflare/internal/controller/leaked/credentialcheck"
	credentialcheckrule "github.com/stakater/provider-cloudflare/internal/controller/leaked/credentialcheckrule"
	item "github.com/stakater/provider-cloudflare/internal/controller/list/item"
	balancer "github.com/stakater/provider-cloudflare/internal/controller/load/balancer"
	balancermonitor "github.com/stakater/provider-cloudflare/internal/controller/load/balancermonitor"
	balancerpool "github.com/stakater/provider-cloudflare/internal/controller/load/balancerpool"
	retention "github.com/stakater/provider-cloudflare/internal/controller/logpull/retention"
	job "github.com/stakater/provider-cloudflare/internal/controller/logpush/job"
	ownershipchallenge "github.com/stakater/provider-cloudflare/internal/controller/logpush/ownershipchallenge"
	networkmonitoringconfiguration "github.com/stakater/provider-cloudflare/internal/controller/magic/networkmonitoringconfiguration"
	networkmonitoringrule "github.com/stakater/provider-cloudflare/internal/controller/magic/networkmonitoringrule"
	transitconnector "github.com/stakater/provider-cloudflare/internal/controller/magic/transitconnector"
	transitsite "github.com/stakater/provider-cloudflare/internal/controller/magic/transitsite"
	transitsiteacl "github.com/stakater/provider-cloudflare/internal/controller/magic/transitsiteacl"
	transitsitelan "github.com/stakater/provider-cloudflare/internal/controller/magic/transitsitelan"
	transitsitewan "github.com/stakater/provider-cloudflare/internal/controller/magic/transitsitewan"
	wangretunnel "github.com/stakater/provider-cloudflare/internal/controller/magic/wangretunnel"
	wanipsectunnel "github.com/stakater/provider-cloudflare/internal/controller/magic/wanipsectunnel"
	wanstaticroute "github.com/stakater/provider-cloudflare/internal/controller/magic/wanstaticroute"
	transforms "github.com/stakater/provider-cloudflare/internal/controller/managed/transforms"
	certificatemtls "github.com/stakater/provider-cloudflare/internal/controller/mtls/certificate"
	policy "github.com/stakater/provider-cloudflare/internal/controller/notification/policy"
	policywebhooks "github.com/stakater/provider-cloudflare/internal/controller/notification/policywebhooks"
	scheduledtest "github.com/stakater/provider-cloudflare/internal/controller/observatory/scheduledtest"
	cacertificate "github.com/stakater/provider-cloudflare/internal/controller/origin/cacertificate"
	rulepage "github.com/stakater/provider-cloudflare/internal/controller/page/rule"
	shieldpolicy "github.com/stakater/provider-cloudflare/internal/controller/page/shieldpolicy"
	domain "github.com/stakater/provider-cloudflare/internal/controller/pages/domain"
	project "github.com/stakater/provider-cloudflare/internal/controller/pages/project"
	providerconfig "github.com/stakater/provider-cloudflare/internal/controller/providerconfig"
	consumer "github.com/stakater/provider-cloudflare/internal/controller/queue/consumer"
	bucket "github.com/stakater/provider-cloudflare/internal/controller/r2/bucket"
	bucketcors "github.com/stakater/provider-cloudflare/internal/controller/r2/bucketcors"
	bucketeventnotification "github.com/stakater/provider-cloudflare/internal/controller/r2/bucketeventnotification"
	bucketlifecycle "github.com/stakater/provider-cloudflare/internal/controller/r2/bucketlifecycle"
	bucketlock "github.com/stakater/provider-cloudflare/internal/controller/r2/bucketlock"
	bucketsippy "github.com/stakater/provider-cloudflare/internal/controller/r2/bucketsippy"
	customdomain "github.com/stakater/provider-cloudflare/internal/controller/r2/customdomain"
	manageddomain "github.com/stakater/provider-cloudflare/internal/controller/r2/manageddomain"
	limit "github.com/stakater/provider-cloudflare/internal/controller/rate/limit"
	hostnameregional "github.com/stakater/provider-cloudflare/internal/controller/regional/hostname"
	tieredcache "github.com/stakater/provider-cloudflare/internal/controller/regional/tieredcache"
	domainregistrar "github.com/stakater/provider-cloudflare/internal/controller/registrar/domain"
	rules "github.com/stakater/provider-cloudflare/internal/controller/snippet/rules"
	application "github.com/stakater/provider-cloudflare/internal/controller/spectrum/application"
	audiotrack "github.com/stakater/provider-cloudflare/internal/controller/stream/audiotrack"
	captionlanguage "github.com/stakater/provider-cloudflare/internal/controller/stream/captionlanguage"
	download "github.com/stakater/provider-cloudflare/internal/controller/stream/download"
	key "github.com/stakater/provider-cloudflare/internal/controller/stream/key"
	liveinput "github.com/stakater/provider-cloudflare/internal/controller/stream/liveinput"
	watermark "github.com/stakater/provider-cloudflare/internal/controller/stream/watermark"
	webhook "github.com/stakater/provider-cloudflare/internal/controller/stream/webhook"
	cache "github.com/stakater/provider-cloudflare/internal/controller/tiered/cache"
	tls "github.com/stakater/provider-cloudflare/internal/controller/total/tls"
	widget "github.com/stakater/provider-cloudflare/internal/controller/turnstile/widget"
	normalizationsettings "github.com/stakater/provider-cloudflare/internal/controller/url/normalizationsettings"
	agentblockingrule "github.com/stakater/provider-cloudflare/internal/controller/user/agentblockingrule"
	room "github.com/stakater/provider-cloudflare/internal/controller/waiting/room"
	roomevent "github.com/stakater/provider-cloudflare/internal/controller/waiting/roomevent"
	roomrules "github.com/stakater/provider-cloudflare/internal/controller/waiting/roomrules"
	roomsettings "github.com/stakater/provider-cloudflare/internal/controller/waiting/roomsettings"
	analyticsrule "github.com/stakater/provider-cloudflare/internal/controller/web/analyticsrule"
	analyticssite "github.com/stakater/provider-cloudflare/internal/controller/web/analyticssite"
	hostnameweb3 "github.com/stakater/provider-cloudflare/internal/controller/web3/hostname"
	crontrigger "github.com/stakater/provider-cloudflare/internal/controller/workers/crontrigger"
	customdomainworkers "github.com/stakater/provider-cloudflare/internal/controller/workers/customdomain"
	deployment "github.com/stakater/provider-cloudflare/internal/controller/workers/deployment"
	forplatformsdispatchnamespace "github.com/stakater/provider-cloudflare/internal/controller/workers/forplatformsdispatchnamespace"
	kv "github.com/stakater/provider-cloudflare/internal/controller/workers/kv"
	kvnamespace "github.com/stakater/provider-cloudflare/internal/controller/workers/kvnamespace"
	route "github.com/stakater/provider-cloudflare/internal/controller/workers/route"
	script "github.com/stakater/provider-cloudflare/internal/controller/workers/script"
	scriptsubdomain "github.com/stakater/provider-cloudflare/internal/controller/workers/scriptsubdomain"
	secret "github.com/stakater/provider-cloudflare/internal/controller/workers/secret"
	trustaccessapplication "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccessapplication"
	trustaccesscustompage "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccesscustompage"
	trustaccessgroup "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccessgroup"
	trustaccessidentityprovider "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccessidentityprovider"
	trustaccessinfrastructuretarget "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccessinfrastructuretarget"
	trustaccesskeyconfiguration "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccesskeyconfiguration"
	trustaccessmtlscertificate "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccessmtlscertificate"
	trustaccessmtlshostnamesettings "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccessmtlshostnamesettings"
	trustaccesspolicy "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccesspolicy"
	trustaccessservicetoken "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccessservicetoken"
	trustaccessshortlivedcertificate "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccessshortlivedcertificate"
	trustaccesstag "github.com/stakater/provider-cloudflare/internal/controller/zero/trustaccesstag"
	trustdevicecustomprofile "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdevicecustomprofile"
	trustdevicecustomprofilelocaldomainfallback "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdevicecustomprofilelocaldomainfallback"
	trustdevicedefaultprofile "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdevicedefaultprofile"
	trustdevicedefaultprofilecertificates "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdevicedefaultprofilecertificates"
	trustdevicedefaultprofilelocaldomainfallback "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdevicedefaultprofilelocaldomainfallback"
	trustdevicemanagednetworks "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdevicemanagednetworks"
	trustdevicepostureintegration "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdevicepostureintegration"
	trustdeviceposturerule "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdeviceposturerule"
	trustdextest "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdextest"
	trustdlpcustomprofile "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdlpcustomprofile"
	trustdlpdataset "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdlpdataset"
	trustdlpentry "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdlpentry"
	trustdlppredefinedprofile "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdlppredefinedprofile"
	trustdnslocation "github.com/stakater/provider-cloudflare/internal/controller/zero/trustdnslocation"
	trustgatewaycertificate "github.com/stakater/provider-cloudflare/internal/controller/zero/trustgatewaycertificate"
	trustgatewaylogging "github.com/stakater/provider-cloudflare/internal/controller/zero/trustgatewaylogging"
	trustgatewaypolicy "github.com/stakater/provider-cloudflare/internal/controller/zero/trustgatewaypolicy"
	trustgatewayproxyendpoint "github.com/stakater/provider-cloudflare/internal/controller/zero/trustgatewayproxyendpoint"
	trustgatewaysettings "github.com/stakater/provider-cloudflare/internal/controller/zero/trustgatewaysettings"
	trustlist "github.com/stakater/provider-cloudflare/internal/controller/zero/trustlist"
	trustorganization "github.com/stakater/provider-cloudflare/internal/controller/zero/trustorganization"
	trustriskbehavior "github.com/stakater/provider-cloudflare/internal/controller/zero/trustriskbehavior"
	trustriskscoringintegration "github.com/stakater/provider-cloudflare/internal/controller/zero/trustriskscoringintegration"
	trusttunnelcloudflared "github.com/stakater/provider-cloudflare/internal/controller/zero/trusttunnelcloudflared"
	trusttunnelcloudflaredconfig "github.com/stakater/provider-cloudflare/internal/controller/zero/trusttunnelcloudflaredconfig"
	trusttunnelcloudflaredroute "github.com/stakater/provider-cloudflare/internal/controller/zero/trusttunnelcloudflaredroute"
	trusttunnelcloudflaredvirtualnetwork "github.com/stakater/provider-cloudflare/internal/controller/zero/trusttunnelcloudflaredvirtualnetwork"
	cachereserve "github.com/stakater/provider-cloudflare/internal/controller/zone/cachereserve"
	cachevariants "github.com/stakater/provider-cloudflare/internal/controller/zone/cachevariants"
	dnssec "github.com/stakater/provider-cloudflare/internal/controller/zone/dnssec"
	hold "github.com/stakater/provider-cloudflare/internal/controller/zone/hold"
	lockdown "github.com/stakater/provider-cloudflare/internal/controller/zone/lockdown"
	setting "github.com/stakater/provider-cloudflare/internal/controller/zone/setting"
	subscriptionzone "github.com/stakater/provider-cloudflare/internal/controller/zone/subscription"
)

// Setup creates all controllers with the supplied logger and adds them to
// the supplied manager.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	for _, setup := range []func(ctrl.Manager, controller.Options) error{
		rule.Setup,
		member.Setup,
		subscription.Setup,
		token.Setup,
		shield.Setup,
		shielddiscoveryoperation.Setup,
		shieldoperation.Setup,
		shieldoperationschemavalidationsettings.Setup,
		shieldschema.Setup,
		shieldschemavalidationsettings.Setup,
		tokenapi.Setup,
		smartrouting.Setup,
		tieredcaching.Setup,
		originpulls.Setup,
		originpullscertificate.Setup,
		management.Setup,
		ipprefix.Setup,
		sfuapp.Setup,
		turnapp.Setup,
		pack.Setup,
		connectorrules.Setup,
		account.Setup,
		filter.Setup,
		healthcheck.Setup,
		image.Setup,
		list.Setup,
		queue.Setup,
		ruleset.Setup,
		snippets.Setup,
		stream.Setup,
		user.Setup,
		zone.Setup,
		onerequest.Setup,
		onerequestasset.Setup,
		onerequestmessage.Setup,
		onerequestpriority.Setup,
		scanningexpression.Setup,
		hostname.Setup,
		hostnamefallbackorigin.Setup,
		ssl.Setup,
		database.Setup,
		firewall.Setup,
		record.Setup,
		settings.Setup,
		settingsinternalview.Setup,
		zonetransfersacl.Setup,
		zonetransfersincoming.Setup,
		zonetransfersoutgoing.Setup,
		zonetransferspeer.Setup,
		zonetransferstsig.Setup,
		routingaddress.Setup,
		routingcatchall.Setup,
		routingdns.Setup,
		routingrule.Setup,
		routingsettings.Setup,
		securityblocksender.Setup,
		securityimpersonationregistry.Setup,
		securitytrusteddomains.Setup,
		rulefirewall.Setup,
		tlssetting.Setup,
		config.Setup,
		variant.Setup,
		certificate.Setup,
		credentialcheck.Setup,
		credentialcheckrule.Setup,
		item.Setup,
		balancer.Setup,
		balancermonitor.Setup,
		balancerpool.Setup,
		retention.Setup,
		job.Setup,
		ownershipchallenge.Setup,
		networkmonitoringconfiguration.Setup,
		networkmonitoringrule.Setup,
		transitconnector.Setup,
		transitsite.Setup,
		transitsiteacl.Setup,
		transitsitelan.Setup,
		transitsitewan.Setup,
		wangretunnel.Setup,
		wanipsectunnel.Setup,
		wanstaticroute.Setup,
		transforms.Setup,
		certificatemtls.Setup,
		policy.Setup,
		policywebhooks.Setup,
		scheduledtest.Setup,
		cacertificate.Setup,
		rulepage.Setup,
		shieldpolicy.Setup,
		domain.Setup,
		project.Setup,
		providerconfig.Setup,
		consumer.Setup,
		bucket.Setup,
		bucketcors.Setup,
		bucketeventnotification.Setup,
		bucketlifecycle.Setup,
		bucketlock.Setup,
		bucketsippy.Setup,
		customdomain.Setup,
		manageddomain.Setup,
		limit.Setup,
		hostnameregional.Setup,
		tieredcache.Setup,
		domainregistrar.Setup,
		rules.Setup,
		application.Setup,
		audiotrack.Setup,
		captionlanguage.Setup,
		download.Setup,
		key.Setup,
		liveinput.Setup,
		watermark.Setup,
		webhook.Setup,
		cache.Setup,
		tls.Setup,
		widget.Setup,
		normalizationsettings.Setup,
		agentblockingrule.Setup,
		room.Setup,
		roomevent.Setup,
		roomrules.Setup,
		roomsettings.Setup,
		analyticsrule.Setup,
		analyticssite.Setup,
		hostnameweb3.Setup,
		crontrigger.Setup,
		customdomainworkers.Setup,
		deployment.Setup,
		forplatformsdispatchnamespace.Setup,
		kv.Setup,
		kvnamespace.Setup,
		route.Setup,
		script.Setup,
		scriptsubdomain.Setup,
		secret.Setup,
		trustaccessapplication.Setup,
		trustaccesscustompage.Setup,
		trustaccessgroup.Setup,
		trustaccessidentityprovider.Setup,
		trustaccessinfrastructuretarget.Setup,
		trustaccesskeyconfiguration.Setup,
		trustaccessmtlscertificate.Setup,
		trustaccessmtlshostnamesettings.Setup,
		trustaccesspolicy.Setup,
		trustaccessservicetoken.Setup,
		trustaccessshortlivedcertificate.Setup,
		trustaccesstag.Setup,
		trustdevicecustomprofile.Setup,
		trustdevicecustomprofilelocaldomainfallback.Setup,
		trustdevicedefaultprofile.Setup,
		trustdevicedefaultprofilecertificates.Setup,
		trustdevicedefaultprofilelocaldomainfallback.Setup,
		trustdevicemanagednetworks.Setup,
		trustdevicepostureintegration.Setup,
		trustdeviceposturerule.Setup,
		trustdextest.Setup,
		trustdlpcustomprofile.Setup,
		trustdlpdataset.Setup,
		trustdlpentry.Setup,
		trustdlppredefinedprofile.Setup,
		trustdnslocation.Setup,
		trustgatewaycertificate.Setup,
		trustgatewaylogging.Setup,
		trustgatewaypolicy.Setup,
		trustgatewayproxyendpoint.Setup,
		trustgatewaysettings.Setup,
		trustlist.Setup,
		trustorganization.Setup,
		trustriskbehavior.Setup,
		trustriskscoringintegration.Setup,
		trusttunnelcloudflared.Setup,
		trusttunnelcloudflaredconfig.Setup,
		trusttunnelcloudflaredroute.Setup,
		trusttunnelcloudflaredvirtualnetwork.Setup,
		cachereserve.Setup,
		cachevariants.Setup,
		dnssec.Setup,
		hold.Setup,
		lockdown.Setup,
		setting.Setup,
		subscriptionzone.Setup,
	} {
		if err := setup(mgr, o); err != nil {
			return err
		}
	}
	return nil
}
