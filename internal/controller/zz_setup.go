// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/upjet/pkg/controller"

	rule "github.com/sibtaina/provider-cloudflare/internal/controller/access/rule"
	member "github.com/sibtaina/provider-cloudflare/internal/controller/account/member"
	subscription "github.com/sibtaina/provider-cloudflare/internal/controller/account/subscription"
	token "github.com/sibtaina/provider-cloudflare/internal/controller/account/token"
	shield "github.com/sibtaina/provider-cloudflare/internal/controller/api/shield"
	shielddiscoveryoperation "github.com/sibtaina/provider-cloudflare/internal/controller/api/shielddiscoveryoperation"
	shieldoperation "github.com/sibtaina/provider-cloudflare/internal/controller/api/shieldoperation"
	shieldoperationschemavalidationsettings "github.com/sibtaina/provider-cloudflare/internal/controller/api/shieldoperationschemavalidationsettings"
	shieldschema "github.com/sibtaina/provider-cloudflare/internal/controller/api/shieldschema"
	shieldschemavalidationsettings "github.com/sibtaina/provider-cloudflare/internal/controller/api/shieldschemavalidationsettings"
	tokenapi "github.com/sibtaina/provider-cloudflare/internal/controller/api/token"
	smartrouting "github.com/sibtaina/provider-cloudflare/internal/controller/argo/smartrouting"
	tieredcaching "github.com/sibtaina/provider-cloudflare/internal/controller/argo/tieredcaching"
	originpulls "github.com/sibtaina/provider-cloudflare/internal/controller/authenticated/originpulls"
	originpullscertificate "github.com/sibtaina/provider-cloudflare/internal/controller/authenticated/originpullscertificate"
	management "github.com/sibtaina/provider-cloudflare/internal/controller/bot/management"
	ipprefix "github.com/sibtaina/provider-cloudflare/internal/controller/byo/ipprefix"
	sfuapp "github.com/sibtaina/provider-cloudflare/internal/controller/calls/sfuapp"
	turnapp "github.com/sibtaina/provider-cloudflare/internal/controller/calls/turnapp"
	pack "github.com/sibtaina/provider-cloudflare/internal/controller/certificate/pack"
	connectorrules "github.com/sibtaina/provider-cloudflare/internal/controller/cloud/connectorrules"
	account "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/account"
	filter "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/filter"
	healthcheck "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/healthcheck"
	image "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/image"
	list "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/list"
	queue "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/queue"
	ruleset "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/ruleset"
	snippets "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/snippets"
	stream "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/stream"
	user "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/user"
	zone "github.com/sibtaina/provider-cloudflare/internal/controller/cloudflare/zone"
	onerequest "github.com/sibtaina/provider-cloudflare/internal/controller/cloudforce/onerequest"
	onerequestasset "github.com/sibtaina/provider-cloudflare/internal/controller/cloudforce/onerequestasset"
	onerequestmessage "github.com/sibtaina/provider-cloudflare/internal/controller/cloudforce/onerequestmessage"
	onerequestpriority "github.com/sibtaina/provider-cloudflare/internal/controller/cloudforce/onerequestpriority"
	scanningexpression "github.com/sibtaina/provider-cloudflare/internal/controller/content/scanningexpression"
	hostname "github.com/sibtaina/provider-cloudflare/internal/controller/custom/hostname"
	hostnamefallbackorigin "github.com/sibtaina/provider-cloudflare/internal/controller/custom/hostnamefallbackorigin"
	ssl "github.com/sibtaina/provider-cloudflare/internal/controller/custom/ssl"
	database "github.com/sibtaina/provider-cloudflare/internal/controller/d1/database"
	firewall "github.com/sibtaina/provider-cloudflare/internal/controller/dns/firewall"
	record "github.com/sibtaina/provider-cloudflare/internal/controller/dns/record"
	settings "github.com/sibtaina/provider-cloudflare/internal/controller/dns/settings"
	settingsinternalview "github.com/sibtaina/provider-cloudflare/internal/controller/dns/settingsinternalview"
	zonetransfersacl "github.com/sibtaina/provider-cloudflare/internal/controller/dns/zonetransfersacl"
	zonetransfersincoming "github.com/sibtaina/provider-cloudflare/internal/controller/dns/zonetransfersincoming"
	zonetransfersoutgoing "github.com/sibtaina/provider-cloudflare/internal/controller/dns/zonetransfersoutgoing"
	zonetransferspeer "github.com/sibtaina/provider-cloudflare/internal/controller/dns/zonetransferspeer"
	zonetransferstsig "github.com/sibtaina/provider-cloudflare/internal/controller/dns/zonetransferstsig"
	routingaddress "github.com/sibtaina/provider-cloudflare/internal/controller/email/routingaddress"
	routingcatchall "github.com/sibtaina/provider-cloudflare/internal/controller/email/routingcatchall"
	routingdns "github.com/sibtaina/provider-cloudflare/internal/controller/email/routingdns"
	routingrule "github.com/sibtaina/provider-cloudflare/internal/controller/email/routingrule"
	routingsettings "github.com/sibtaina/provider-cloudflare/internal/controller/email/routingsettings"
	securityblocksender "github.com/sibtaina/provider-cloudflare/internal/controller/email/securityblocksender"
	securityimpersonationregistry "github.com/sibtaina/provider-cloudflare/internal/controller/email/securityimpersonationregistry"
	securitytrusteddomains "github.com/sibtaina/provider-cloudflare/internal/controller/email/securitytrusteddomains"
	rulefirewall "github.com/sibtaina/provider-cloudflare/internal/controller/firewall/rule"
	tlssetting "github.com/sibtaina/provider-cloudflare/internal/controller/hostname/tlssetting"
	config "github.com/sibtaina/provider-cloudflare/internal/controller/hyperdrive/config"
	variant "github.com/sibtaina/provider-cloudflare/internal/controller/image/variant"
	certificate "github.com/sibtaina/provider-cloudflare/internal/controller/keyless/certificate"
	credentialcheck "github.com/sibtaina/provider-cloudflare/internal/controller/leaked/credentialcheck"
	credentialcheckrule "github.com/sibtaina/provider-cloudflare/internal/controller/leaked/credentialcheckrule"
	item "github.com/sibtaina/provider-cloudflare/internal/controller/list/item"
	balancer "github.com/sibtaina/provider-cloudflare/internal/controller/load/balancer"
	balancermonitor "github.com/sibtaina/provider-cloudflare/internal/controller/load/balancermonitor"
	balancerpool "github.com/sibtaina/provider-cloudflare/internal/controller/load/balancerpool"
	retention "github.com/sibtaina/provider-cloudflare/internal/controller/logpull/retention"
	job "github.com/sibtaina/provider-cloudflare/internal/controller/logpush/job"
	ownershipchallenge "github.com/sibtaina/provider-cloudflare/internal/controller/logpush/ownershipchallenge"
	networkmonitoringconfiguration "github.com/sibtaina/provider-cloudflare/internal/controller/magic/networkmonitoringconfiguration"
	networkmonitoringrule "github.com/sibtaina/provider-cloudflare/internal/controller/magic/networkmonitoringrule"
	transitconnector "github.com/sibtaina/provider-cloudflare/internal/controller/magic/transitconnector"
	transitsite "github.com/sibtaina/provider-cloudflare/internal/controller/magic/transitsite"
	transitsiteacl "github.com/sibtaina/provider-cloudflare/internal/controller/magic/transitsiteacl"
	transitsitelan "github.com/sibtaina/provider-cloudflare/internal/controller/magic/transitsitelan"
	transitsitewan "github.com/sibtaina/provider-cloudflare/internal/controller/magic/transitsitewan"
	wangretunnel "github.com/sibtaina/provider-cloudflare/internal/controller/magic/wangretunnel"
	wanipsectunnel "github.com/sibtaina/provider-cloudflare/internal/controller/magic/wanipsectunnel"
	wanstaticroute "github.com/sibtaina/provider-cloudflare/internal/controller/magic/wanstaticroute"
	transforms "github.com/sibtaina/provider-cloudflare/internal/controller/managed/transforms"
	certificatemtls "github.com/sibtaina/provider-cloudflare/internal/controller/mtls/certificate"
	policy "github.com/sibtaina/provider-cloudflare/internal/controller/notification/policy"
	policywebhooks "github.com/sibtaina/provider-cloudflare/internal/controller/notification/policywebhooks"
	scheduledtest "github.com/sibtaina/provider-cloudflare/internal/controller/observatory/scheduledtest"
	cacertificate "github.com/sibtaina/provider-cloudflare/internal/controller/origin/cacertificate"
	rulepage "github.com/sibtaina/provider-cloudflare/internal/controller/page/rule"
	shieldpolicy "github.com/sibtaina/provider-cloudflare/internal/controller/page/shieldpolicy"
	domain "github.com/sibtaina/provider-cloudflare/internal/controller/pages/domain"
	project "github.com/sibtaina/provider-cloudflare/internal/controller/pages/project"
	providerconfig "github.com/sibtaina/provider-cloudflare/internal/controller/providerconfig"
	consumer "github.com/sibtaina/provider-cloudflare/internal/controller/queue/consumer"
	bucket "github.com/sibtaina/provider-cloudflare/internal/controller/r2/bucket"
	bucketcors "github.com/sibtaina/provider-cloudflare/internal/controller/r2/bucketcors"
	bucketeventnotification "github.com/sibtaina/provider-cloudflare/internal/controller/r2/bucketeventnotification"
	bucketlifecycle "github.com/sibtaina/provider-cloudflare/internal/controller/r2/bucketlifecycle"
	bucketlock "github.com/sibtaina/provider-cloudflare/internal/controller/r2/bucketlock"
	bucketsippy "github.com/sibtaina/provider-cloudflare/internal/controller/r2/bucketsippy"
	customdomain "github.com/sibtaina/provider-cloudflare/internal/controller/r2/customdomain"
	manageddomain "github.com/sibtaina/provider-cloudflare/internal/controller/r2/manageddomain"
	limit "github.com/sibtaina/provider-cloudflare/internal/controller/rate/limit"
	hostnameregional "github.com/sibtaina/provider-cloudflare/internal/controller/regional/hostname"
	tieredcache "github.com/sibtaina/provider-cloudflare/internal/controller/regional/tieredcache"
	domainregistrar "github.com/sibtaina/provider-cloudflare/internal/controller/registrar/domain"
	rules "github.com/sibtaina/provider-cloudflare/internal/controller/snippet/rules"
	application "github.com/sibtaina/provider-cloudflare/internal/controller/spectrum/application"
	audiotrack "github.com/sibtaina/provider-cloudflare/internal/controller/stream/audiotrack"
	captionlanguage "github.com/sibtaina/provider-cloudflare/internal/controller/stream/captionlanguage"
	download "github.com/sibtaina/provider-cloudflare/internal/controller/stream/download"
	key "github.com/sibtaina/provider-cloudflare/internal/controller/stream/key"
	liveinput "github.com/sibtaina/provider-cloudflare/internal/controller/stream/liveinput"
	watermark "github.com/sibtaina/provider-cloudflare/internal/controller/stream/watermark"
	webhook "github.com/sibtaina/provider-cloudflare/internal/controller/stream/webhook"
	cache "github.com/sibtaina/provider-cloudflare/internal/controller/tiered/cache"
	tls "github.com/sibtaina/provider-cloudflare/internal/controller/total/tls"
	widget "github.com/sibtaina/provider-cloudflare/internal/controller/turnstile/widget"
	normalizationsettings "github.com/sibtaina/provider-cloudflare/internal/controller/url/normalizationsettings"
	agentblockingrule "github.com/sibtaina/provider-cloudflare/internal/controller/user/agentblockingrule"
	room "github.com/sibtaina/provider-cloudflare/internal/controller/waiting/room"
	roomevent "github.com/sibtaina/provider-cloudflare/internal/controller/waiting/roomevent"
	roomrules "github.com/sibtaina/provider-cloudflare/internal/controller/waiting/roomrules"
	roomsettings "github.com/sibtaina/provider-cloudflare/internal/controller/waiting/roomsettings"
	analyticsrule "github.com/sibtaina/provider-cloudflare/internal/controller/web/analyticsrule"
	analyticssite "github.com/sibtaina/provider-cloudflare/internal/controller/web/analyticssite"
	hostnameweb3 "github.com/sibtaina/provider-cloudflare/internal/controller/web3/hostname"
	crontrigger "github.com/sibtaina/provider-cloudflare/internal/controller/workers/crontrigger"
	customdomainworkers "github.com/sibtaina/provider-cloudflare/internal/controller/workers/customdomain"
	deployment "github.com/sibtaina/provider-cloudflare/internal/controller/workers/deployment"
	forplatformsdispatchnamespace "github.com/sibtaina/provider-cloudflare/internal/controller/workers/forplatformsdispatchnamespace"
	kv "github.com/sibtaina/provider-cloudflare/internal/controller/workers/kv"
	kvnamespace "github.com/sibtaina/provider-cloudflare/internal/controller/workers/kvnamespace"
	route "github.com/sibtaina/provider-cloudflare/internal/controller/workers/route"
	script "github.com/sibtaina/provider-cloudflare/internal/controller/workers/script"
	scriptsubdomain "github.com/sibtaina/provider-cloudflare/internal/controller/workers/scriptsubdomain"
	secret "github.com/sibtaina/provider-cloudflare/internal/controller/workers/secret"
	trustaccessapplication "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccessapplication"
	trustaccesscustompage "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccesscustompage"
	trustaccessgroup "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccessgroup"
	trustaccessidentityprovider "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccessidentityprovider"
	trustaccessinfrastructuretarget "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccessinfrastructuretarget"
	trustaccesskeyconfiguration "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccesskeyconfiguration"
	trustaccessmtlscertificate "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccessmtlscertificate"
	trustaccessmtlshostnamesettings "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccessmtlshostnamesettings"
	trustaccesspolicy "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccesspolicy"
	trustaccessservicetoken "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccessservicetoken"
	trustaccessshortlivedcertificate "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccessshortlivedcertificate"
	trustaccesstag "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustaccesstag"
	trustdevicecustomprofile "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdevicecustomprofile"
	trustdevicecustomprofilelocaldomainfallback "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdevicecustomprofilelocaldomainfallback"
	trustdevicedefaultprofile "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdevicedefaultprofile"
	trustdevicedefaultprofilecertificates "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdevicedefaultprofilecertificates"
	trustdevicedefaultprofilelocaldomainfallback "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdevicedefaultprofilelocaldomainfallback"
	trustdevicemanagednetworks "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdevicemanagednetworks"
	trustdevicepostureintegration "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdevicepostureintegration"
	trustdeviceposturerule "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdeviceposturerule"
	trustdextest "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdextest"
	trustdlpcustomprofile "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdlpcustomprofile"
	trustdlpdataset "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdlpdataset"
	trustdlpentry "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdlpentry"
	trustdlppredefinedprofile "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdlppredefinedprofile"
	trustdnslocation "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustdnslocation"
	trustgatewaycertificate "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustgatewaycertificate"
	trustgatewaylogging "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustgatewaylogging"
	trustgatewaypolicy "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustgatewaypolicy"
	trustgatewayproxyendpoint "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustgatewayproxyendpoint"
	trustgatewaysettings "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustgatewaysettings"
	trustlist "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustlist"
	trustorganization "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustorganization"
	trustriskbehavior "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustriskbehavior"
	trustriskscoringintegration "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trustriskscoringintegration"
	trusttunnelcloudflared "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trusttunnelcloudflared"
	trusttunnelcloudflaredconfig "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trusttunnelcloudflaredconfig"
	trusttunnelcloudflaredroute "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trusttunnelcloudflaredroute"
	trusttunnelcloudflaredvirtualnetwork "github.com/sibtaina/provider-cloudflare/internal/controller/zero/trusttunnelcloudflaredvirtualnetwork"
	cachereserve "github.com/sibtaina/provider-cloudflare/internal/controller/zone/cachereserve"
	cachevariants "github.com/sibtaina/provider-cloudflare/internal/controller/zone/cachevariants"
	dnssec "github.com/sibtaina/provider-cloudflare/internal/controller/zone/dnssec"
	hold "github.com/sibtaina/provider-cloudflare/internal/controller/zone/hold"
	lockdown "github.com/sibtaina/provider-cloudflare/internal/controller/zone/lockdown"
	setting "github.com/sibtaina/provider-cloudflare/internal/controller/zone/setting"
	subscriptionzone "github.com/sibtaina/provider-cloudflare/internal/controller/zone/subscription"
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
