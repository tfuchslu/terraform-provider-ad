package ad

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func rescourceADSecPrincipal() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_security_prinicipal` manages the security pricipals of a given Active Directory.",
		Create:      rescourceADSecPrincipalCreate,
		Read:        rescourceADSecPrincipalRead,
		Update:      rescourceADSecPrincipalUpdate,
		Delete:      rescourceADSecPrincipalDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"object_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The ID of the group. This can be a GUID, a SID, a Distinguished Name, or the SAM Account Name of the group.",
				ForceNew:    true,
			},
			"group_members": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "A list of member AD Principals. Each principal can be identified by its GUID, SID, Distinguished Name, or SAM Account Name. Only one is required",
				Elem:        &schema.Schema{Type: schema.TypeString},
				MinItems:    1,
			},
		},
	}
}

func rescourceADSecPrincipalRead(d *schema.ResourceData, meta interface{}) error {
	toks := strings.Split(d.Id(), "_")

	gm, err := winrmhelper.NewGroupMembershipFromHost(meta.(*config.ProviderConf), toks[0])
	if err != nil {
		return err
	}
	memberList := make([]string, len(gm.GroupMembers))

	for idx, m := range gm.GroupMembers {
		memberList[idx] = m.GUID
	}
	_ = d.Set("group_members", memberList)
	_ = d.Set("group_id", toks[0])
	return nil
}

func rescourceADSecPrincipalCreate(d *schema.ResourceData, meta interface{}) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Create(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	membershipUUID, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("while generating UUID to use as unique membership ID: %s", err)
	}

	id := fmt.Sprintf("%s_%s", gm.GroupGUID, membershipUUID)
	d.SetId(id)

	return nil
}

func rescourceADSecPrincipalUpdate(d *schema.ResourceData, meta interface{}) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Update(meta.(*config.ProviderConf), gm.GroupMembers)
	if err != nil {
		return err
	}

	return resourceADGroupMembershipRead(d, meta)
}

func rescourceADSecPrincipalDelete(d *schema.ResourceData, meta interface{}) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Delete(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}
