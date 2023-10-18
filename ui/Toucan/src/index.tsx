import React, { useContext, useState } from 'react';
import ReactDOM from 'react-dom';
import { AyxAppWrapper, Box, FormControl, Grid, Input, InputLabel, Typography, makeStyles, Theme } from '@alteryx/ui';
import { Context as UiSdkContext, DesignerApi } from '@alteryx/react-comms';

interface ToucanInputs {
  baseroute: string;
  appId: string;
  opaqueToken: string;
  datasetName: string;
};

const useStyles = makeStyles((theme: Theme) => ({
  toucan: {
    height: '125px',
    width: '125px'
  }
}));

const App = () => {
  const classes = useStyles();
  const [model, handleUpdateModel] = useContext(UiSdkContext);
  const handleChange = (field: keyof ToucanInputs) => (event) => {
    handleUpdateModel({ ...model, Configuration: { ...model.Configuration, [field]: event.target.value } });
  };

  return (
    <Box p={4}>
      <Grid container spacing={4} direction="column" alignItems="center">
        <Grid item>
          <FormControl>
            <InputLabel htmlFor="baseroute-input">Baseroute</InputLabel>
            <Input
              id="baseroute-input"
              onChange={handleChange('baseroute')}
            />
          </FormControl>
        </Grid>
        <Grid item>
          <FormControl>
            <InputLabel htmlFor="app-id-input">App id</InputLabel>
            <Input
              id="app-id-input"
              onChange={handleChange('appId')}
            />
          </FormControl>
        </Grid>
        <Grid item>
          <FormControl>
            <InputLabel htmlFor="dataset-name-input">Dataset name</InputLabel>
            <Input
              id="dataset-name-input"
              onChange={handleChange('datasetName')}
            />
          </FormControl>
        </Grid>
        <Grid item>
          <FormControl>
            <InputLabel htmlFor="opaque-token-input">Opaque token</InputLabel>
            <Input
              id="opaque-token-input"
              onChange={handleChange('opaqueToken')}
            />
          </FormControl>
        </Grid>
      </Grid>
    </Box>
  )
}

const Tool = () => {
  return (
    <DesignerApi messages={{}}>
      <AyxAppWrapper> 
        <App />
      </AyxAppWrapper>
    </DesignerApi>
  )
}

ReactDOM.render(
  <Tool />,
  document.getElementById('app')
);
