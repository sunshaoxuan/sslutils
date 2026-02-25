@{
    # Root directory for certificate storage (relative to script root)
    CertStoreRoot = "CertStore"

    # Agencies configuration
    Agencies      = @{
        "NII"        = @{
            Path     = "NII"
            Patterns = @("nii*.cer", "nii*.crt", "nii*.pem")
        }
        "GlobalSign" = @{
            Path     = "GlobalSign"
            Patterns = @("gs*.cer", "gs*.crt", "gs*.pem", "globalsign*.cer", "globalsign*.crt", "globalsign*.pem")
        }
        "Secom"      = @{
            Path     = "Secom"
            Patterns = @("secom*.cer", "secom*.crt", "secom*.pem")
        }
    }
}
