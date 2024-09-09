package user

import (
	"context"
	"github.com/auth0/go-auth0/management"
	"github.com/auth0/terraform-provider-auth0/internal/config"
	internalError "github.com/auth0/terraform-provider-auth0/internal/error"
	internalSchema "github.com/auth0/terraform-provider-auth0/internal/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// NewAuthenticationMethodResource will return a new auth0_connection_client resource.
func NewAuthenticationMethodResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"user_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the user to associate the permission to.",
			},
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The type of the authentication method.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "A human-readable label to identify the authentication method.",
			},
			"totp_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Sensitive:   true,
				Description: "Base32 encoded secret for TOTP generation.",
			},
		},
		CreateContext: createUserAuthenticationMethod,
		ReadContext:   readUserAuthenticationMethod,
		DeleteContext: deleteUserAuthenticationMethod,
		Importer: &schema.ResourceImporter{
			StateContext: internalSchema.ImportResourceGroupID("user_id", "resource_server_identifier", "permission"),
		},
		Description: "With this resource, you can manage user authentication methods.",
	}
}

func createUserAuthenticationMethod(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	api := meta.(*config.Config).GetAPI()

	userID := data.Get("user_id").(string)
	authType := data.Get("type").(string)
	name := data.Get("name").(string)
	totpSecret := data.Get("totp_secret").(string)

	if err := api.User.CreateAuthenticationMethod(ctx, userID, &management.AuthenticationMethod{
		Type:       &authType,
		Name:       &name,
		TOTPSecret: &totpSecret,
	}); err != nil {
		return diag.FromErr(err)
	}

	id, err := getUserAuthenticationMethodID(ctx, data, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	data.SetId(id)
	return readUserAuthenticationMethod(ctx, data, meta)
}

func readUserAuthenticationMethod(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	api := meta.(*config.Config).GetAPI()

	userID := data.Get("user_id").(string)
	id := data.Id()

	authMethods, err := api.User.ListAuthenticationMethods(ctx, userID)
	if err != nil {
		return diag.FromErr(internalError.HandleAPIError(data, err))
	}

	for _, authMethod := range authMethods.Authenticators {
		if *authMethod.ID == id {
			return nil
		}
	}

	if !data.IsNewResource() {
		data.SetId("")
	}

	return nil
	//return diag.FromErr(fmt.Errorf("Expected to have found something"))
}

func deleteUserAuthenticationMethod(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	api := meta.(*config.Config).GetAPI()

	userID := data.Get("user_id").(string)
	id := data.Id()

	if err := api.User.DeleteAuthenticationMethod(ctx, userID, id); err != nil {
		return diag.FromErr(internalError.HandleAPIError(data, err))
	}

	return nil
}

func getUserAuthenticationMethodID(ctx context.Context, data *schema.ResourceData, meta interface{}) (string, error) {
	api := meta.(*config.Config).GetAPI()

	userID := data.Get("user_id").(string)
	authType := data.Get("type").(string)
	name := data.Get("name").(string)

	authMethods, err := api.User.ListAuthenticationMethods(ctx, userID)
	if err != nil {
		return "", err
	}

	for _, authMethod := range authMethods.Authenticators {
		if *authMethod.Name == name && *authMethod.Type == authType {
			return *authMethod.ID, nil
		}
	}

	return "NOTFOUND", nil
}
